from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef, EngineConfig
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.result_review import ResultReviewExecutor, ResultReviewFrameworkError
from app.pi_vuln_core.review.result_review_parser import parse_result_review_response
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.vulnerability_list import load_vulnerability_list


def test_result_review_parser_treats_partially_valid_as_confirmed_truth() -> None:
    content = '''
    {
      "verification_result": "PARTIALLY_VALID",
      "confidence": "HIGH",
      "summary": "底层边界检查缺陷真实存在，但报告把严重度和可利用性写高了。"
    }
    '''
    outcome = parse_result_review_response(content)
    assert outcome.parsed.passed is True
    assert outcome.parsed.verdict == "CONFIRMED"
    assert outcome.parsed.confidence >= 0.8
    assert outcome.schema_valid is False


def test_result_review_parser_treats_confirmed_with_modifications_as_confirmed_truth() -> None:
    content = '''
    {
      "verification_result": "CONFIRMED_WITH_MODIFICATIONS",
      "confidence": "HIGH",
      "summary": "漏洞确实存在，但只能在高权限/配置错误前提下触发。",
      "final_verdict": {
        "vulnerability_confirmed": true,
        "severity_correct": false,
        "attack_scenario_invalid": true,
        "data_flow_claim_incorrect": true
      }
    }
    '''
    outcome = parse_result_review_response(content)
    assert outcome.parsed.passed is True
    assert outcome.parsed.verdict == "CONFIRMED"
    assert "漏洞确实存在" in outcome.parsed.feedback_detail


def test_result_review_parser_keeps_false_positive_strict() -> None:
    content = '''
    {
      "verification_result": "FALSE_POSITIVE",
      "confidence": "HIGH",
      "summary": "报告遗漏了完整的上游长度检查，底层问题不存在。"
    }
    '''
    outcome = parse_result_review_response(content)
    assert outcome.parsed.passed is False
    assert outcome.parsed.verdict == "FALSE_POSITIVE"
    assert outcome.parsed.confidence >= 0.8


def test_result_review_parser_rejects_insufficient_info_verdict() -> None:
    content = '''
    {
      "passed": false,
      "verdict": "INSUFFICIENT_INFO",
      "feedback": "证据不足，无法判断",
      "scores": {"issue_truth": 0.4},
      "confidence": 0.6
    }
    '''
    outcome = parse_result_review_response(content)
    assert outcome.schema_valid is False
    assert outcome.needs_repair is True
    assert "CONFIRMED 或 FALSE_POSITIVE" in outcome.repair_reason


class RepairingTruthRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.call_count = 0

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"truth_{len(self._sessions) + 1}"
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

        if "未满足框架 schema" in message:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "底层问题真实存在，但严重度和攻击路径描述需要下调。",
                    "scores": {"issue_truth": 0.86},
                    "confidence": 0.86,
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "verification_result": "PARTIALLY_VALID",
                    "summary": "底层问题真实存在，但严重度和攻击路径描述需要下调。",
                    "confidence": "HIGH",
                },
                ensure_ascii=False,
            )

        return AgentResponse(
            content=content,
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


class ExplicitPassedAliasRuntime(RepairingTruthRuntime):
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

        if "未满足框架 schema" in message:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "这是补充分析，但底层问题真实存在。",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "VALID_CORRECTION",
                    "feedback": "这是补充分析，但底层问题真实存在。",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class InsufficientThenFalsePositiveRuntime(RepairingTruthRuntime):
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

        if "未满足框架 schema" in message:
            content = json.dumps(
                {
                    "passed": False,
                    "verdict": "FALSE_POSITIVE",
                    "feedback": "现有代码证据显示报告声称的问题不存在。",
                    "scores": {"issue_truth": 0.1},
                    "confidence": 0.8,
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "passed": False,
                    "verdict": "INSUFFICIENT_INFO",
                    "feedback": "证据不足，无法判断。",
                    "scores": {"issue_truth": 0.4},
                    "confidence": 0.6,
                },
                ensure_ascii=False,
            )

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class UnrepairableNonCanonicalRuntime(RepairingTruthRuntime):
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

        content = json.dumps(
            {
                "passed": True,
                "verdict": "REAL",
                "feedback": "底层问题真实存在，但我拒绝按 schema 输出。",
                "scores": {"truth": 0.9},
                "confidence": "HIGH",
            },
            ensure_ascii=False,
        )
        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class FreshSessionTruthRuntime(RepairingTruthRuntime):
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

        if "新的修复会话" in message:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "新会话重编码成功，底层问题真实存在。",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.88,
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "verification_result": "PARTIALLY_VALID",
                    "summary": "底层问题真实存在，但我先不按 canonical schema 输出。",
                    "confidence": "HIGH",
                },
                ensure_ascii=False,
            )

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


@pytest.mark.asyncio
async def test_result_review_accepts_real_issue_even_when_initial_response_is_partial_and_noncanonical(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", RepairingTruthRuntime)

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
    (results_dir / "result_001.md").write_text("# result\n\ncontent\n", encoding="utf-8")

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
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
        engine_config=EngineConfig(result_review_fresh_session_schema_repair_limit=0),
    )

    assert all_passed is True
    assert failed_items == []

    review_json = json.loads(
        (tmp_path / "reviews" / "results" / "result_001" / "cycle_001" / "result_fp_check.json").read_text(
            encoding="utf-8"
        )
    )
    assert review_json["passed"] is True
    assert review_json["verdict"] == "CONFIRMED"
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 1
    assert "schema_repair_attempt_1" in review_json["raw_response"]
    vuln_entry = load_vulnerability_list(tmp_path)["entries"][0]
    assert vuln_entry["status"] == "confirmed"
    assert "底层问题真实存在" in vuln_entry["review_feedback"]

    runtime = registry.get("advisor-agent")
    assert runtime.call_count == 2

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_repairs_explicit_passed_alias_into_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", ExplicitPassedAliasRuntime)

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
    (results_dir / "result_011.md").write_text("# result\n\ncontent\n", encoding="utf-8")

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
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
        engine_config=EngineConfig(result_review_fresh_session_schema_repair_limit=0),
    )

    assert all_passed is True
    assert failed_items == []

    review_json = json.loads(
        (tmp_path / "reviews" / "results" / "result_011" / "cycle_001" / "result_fp_check.json").read_text(
            encoding="utf-8"
        )
    )
    assert review_json["passed"] is True
    assert review_json["verdict"] == "CONFIRMED"
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 1
    assert "VALID_CORRECTION" in review_json["raw_response"]
    assert "schema_repair_attempt_1" in review_json["raw_response"]

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_repairs_insufficient_info_into_binary_verdict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", InsufficientThenFalsePositiveRuntime)

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
    (results_dir / "result_012.md").write_text("# result\n\ncontent\n", encoding="utf-8")

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
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
        engine_config=EngineConfig(result_review_fresh_session_schema_repair_limit=0),
    )

    assert all_passed is True
    assert failed_items == []

    review_json = json.loads(
        (tmp_path / "reviews" / "results" / "result_012" / "cycle_001" / "result_fp_check.json").read_text(
            encoding="utf-8"
        )
    )
    assert review_json["passed"] is False
    assert review_json["verdict"] == "FALSE_POSITIVE"
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 1
    assert "INSUFFICIENT_INFO" in review_json["raw_response"]

    vuln_entry = load_vulnerability_list(tmp_path)["entries"][0]
    assert vuln_entry["status"] == "false_positive"
    assert vuln_entry["verdict"] == "FALSE_POSITIVE"
    assert vuln_entry["status_label"] == "误报"

    runtime = registry.get("advisor-agent")
    assert runtime.call_count == 2

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_fails_close_when_agent_refuses_canonical_schema_after_repairs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", UnrepairableNonCanonicalRuntime)

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
    (results_dir / "result_001.md").write_text("# result\n\ncontent\n", encoding="utf-8")

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
            engine_config=EngineConfig(result_review_fresh_session_schema_repair_limit=0),
        )

    assert exc_info.value.error_code == "result_review_schema_invalid"

    review_json = json.loads(
        (tmp_path / "reviews" / "results" / "result_001" / "cycle_001" / "result_fp_check.json").read_text(
            encoding="utf-8"
        )
    )
    assert review_json["passed"] is False
    assert review_json["verdict"] == "ERROR"
    assert review_json["schema_valid"] is False
    assert review_json["repair_attempts"] == 2
    assert "schema_repair_attempt_2" in review_json["raw_response"]

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_uses_fresh_session_schema_repair_after_same_session_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", FreshSessionTruthRuntime)

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
    (results_dir / "result_013.md").write_text("# result\n\ncontent\n", encoding="utf-8")

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
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
        engine_config=EngineConfig(
            result_review_schema_repair_limit=1,
            result_review_fresh_session_schema_repair_limit=1,
        ),
    )

    assert all_passed is True
    assert failed_items == []

    review_json = json.loads(
        (tmp_path / "reviews" / "results" / "result_013" / "cycle_001" / "result_fp_check.json").read_text(
            encoding="utf-8"
        )
    )
    assert review_json["passed"] is True
    assert review_json["verdict"] == "CONFIRMED"
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 2
    assert "fresh_session_schema_repair_attempt_1" in review_json["raw_response"]

    runtime = registry.get("advisor-agent")
    assert runtime.call_count == 3

    await registry.shutdown_all()
