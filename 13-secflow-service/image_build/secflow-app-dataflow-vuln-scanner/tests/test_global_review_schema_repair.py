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
from app.pi_vuln_core.review.global_review_parser import GlobalReviewParseOutcome
from app.pi_vuln_core.review.models import ParsedReviewResult
from app.pi_vuln_core.review.state import ReviewState

ALL_SCORE_FIELDS = [
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "vuln_pattern_breadth",
    "code_evidence_depth",
    "limitations_honesty",
    "report_completeness",
]
ALL_SCORE_THRESHOLDS_START = {
    "input_coverage": 0.8,
    "export_followthrough": 0.7,
    "used_coverage": 0.7,
    "vuln_pattern_breadth": 0.6,
    "code_evidence_depth": 0.6,
    "limitations_honesty": 0.75,
    "report_completeness": 0.7,
}
ALL_SCORE_THRESHOLDS = {
    "input_coverage": 1.0,
    "export_followthrough": 0.95,
    "used_coverage": 0.95,
    "vuln_pattern_breadth": 0.85,
    "code_evidence_depth": 0.85,
    "limitations_honesty": 0.95,
    "report_completeness": 0.9,
}
DEPTH_SCORE_FIELDS = ["vuln_pattern_breadth"]
DEPTH_SCORE_THRESHOLDS_START = {
    "vuln_pattern_breadth": 0.6,
}
DEPTH_SCORE_THRESHOLDS = {
    "vuln_pattern_breadth": 0.85,
}
COMPLETENESS_SCORE_FIELDS = [
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "limitations_honesty",
    "report_completeness",
]
COMPLETENESS_SCORE_THRESHOLDS_START = {
    key: ALL_SCORE_THRESHOLDS_START[key]
    for key in COMPLETENESS_SCORE_FIELDS
}
COMPLETENESS_SCORE_THRESHOLDS = {
    key: ALL_SCORE_THRESHOLDS[key]
    for key in COMPLETENESS_SCORE_FIELDS
}


class RepairingGlobalRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.call_count = 0

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"global_{len(self._sessions) + 1}"
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
                    "verdict": "PASS",
                    "feedback": "覆盖接近穷尽，局限性披露充分。",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 0.97,
                        "used_coverage": 0.98,
                        "vuln_pattern_breadth": 0.9,
                        "code_evidence_depth": 0.91,
                        "limitations_honesty": 0.97,
                        "report_completeness": 0.95,
                    },
                    "confidence": 0.93,
                    "issues": [],
                    "resolved_issues": [],
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "覆盖接近穷尽，局限性披露充分。",
                    "scores": {},
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


class UnrepairableGlobalRuntime(RepairingGlobalRuntime):
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
                "verdict": "PASS",
                "feedback": "我坚持不给完整 scores。",
                "scores": {"input_coverage": 1.0},
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


class DepthOnlyScoreRuntime(RepairingGlobalRuntime):
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
                "verdict": "PASS",
                "feedback": "depth evidence is sufficient",
                "scores": {
                    "vuln_pattern_breadth": 0.95,
                },
                "confidence": 0.94,
                "issues": [],
                "resolved_issues": [],
            },
            ensure_ascii=False,
        )
        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class DepthExtraLowCoverageRuntime(RepairingGlobalRuntime):
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
                "verdict": "PASS",
                "feedback": "depth-owned scores pass; extra coverage scores are advisory only for this role",
                "scores": {
                    "input_coverage": 0.10,
                    "export_followthrough": 0.10,
                    "used_coverage": 0.10,
                    "vuln_pattern_breadth": 0.95,
                    "code_evidence_depth": 0.96,
                    "limitations_honesty": 0.10,
                    "report_completeness": 0.10,
                },
                "confidence": 0.94,
                "issues": [],
                "resolved_issues": [],
            },
            ensure_ascii=False,
        )
        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class SplitGlobalRuntime(RepairingGlobalRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.messages: list[str] = []

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
        self.messages.append(message)

        if "advisor_instance_id: global_completeness" in message:
            content = json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "coverage issue resolved",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 1.0,
                        "used_coverage": 1.0,
                        "vuln_pattern_breadth": 0.92,
                        "code_evidence_depth": 0.9,
                        "limitations_honesty": 1.0,
                        "report_completeness": 0.95,
                    },
                    "confidence": 0.92,
                    "issues": [],
                    "resolved_issues": ["CMP-USED-001"],
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "passed": False,
                    "verdict": "FAIL",
                    "feedback": "depth not enough",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 0.97,
                        "used_coverage": 0.97,
                        "vuln_pattern_breadth": 0.70,
                        "code_evidence_depth": 0.80,
                        "limitations_honesty": 0.96,
                        "report_completeness": 0.93,
                    },
                    "confidence": 0.93,
                    "issues": [
                        {
                            "id": "DEP-PATTERN-001",
                            "category": "vuln_pattern_breadth",
                            "target": "worker_system_checklist",
                            "severity": "high",
                            "required_action": "按 worker_system.md 的漏洞挖掘清单补齐模式覆盖，并补充关键校验绕过分析。",
                            "actionable_by": "worker",
                        }
                    ],
                    "resolved_issues": [],
                },
                ensure_ascii=False,
            )

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


async def _run_global_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_cls: type[BaseAgentRuntime],
) -> tuple[bool, str, dict, BaseAgentRuntime]:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", runtime_cls)

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

    work_dir = tmp_path / "atomic"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")
    summary_file = work_dir / "summary.md"
    summary_file.write_text("# summary\n\n## 7. 局限性与未覆盖区域\n", encoding="utf-8")
    task_file = work_dir / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    sys_prompt = tmp_path / "sys.md"
    sys_prompt.write_text("system\n", encoding="utf-8")
    user_prompt = tmp_path / "user.md"
    user_prompt.write_text(
        "review context:\n{review_context}\nrequired: {required_score_fields}\n",
        encoding="utf-8",
    )

    advisor = AdvisorInstanceDef(
        instance_id="global_quality",
        agent_id="advisor-agent",
        role_name="全面性与质量评审",
        re_review_on_cycle=True,
        system_prompt_file=str(sys_prompt),
        user_prompt_template=str(user_prompt),
        score_fields=ALL_SCORE_FIELDS,
        score_thresholds_start=ALL_SCORE_THRESHOLDS_START,
        score_thresholds=ALL_SCORE_THRESHOLDS,
    )

    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    passed, feedback = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=1,
        review_state=review_state,
        advisor_sessions={},
    )

    review_json = json.loads(
        (work_dir / "reviews" / "global" / "cycle_001" / "global_quality.json").read_text(
            encoding="utf-8"
        )
    )
    runtime = registry.get("advisor-agent")
    await registry.shutdown_all()
    return passed, feedback, review_json, runtime


@pytest.mark.asyncio
async def test_global_review_repairs_missing_scores_and_persists_canonical_review_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passed, feedback, review_json, runtime = await _run_global_review(
        monkeypatch,
        tmp_path,
        RepairingGlobalRuntime,
    )

    assert passed is True
    assert feedback == ""
    assert review_json["passed"] is True
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 1
    assert review_json["scores"]["input_coverage"] == 1.0
    assert "schema_repair_attempt_1" in review_json["raw_response"]
    assert runtime.call_count == 2


@pytest.mark.asyncio
async def test_global_review_fail_closes_when_scores_remain_noncanonical_after_repairs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passed, feedback, review_json, runtime = await _run_global_review(
        monkeypatch,
        tmp_path,
        UnrepairableGlobalRuntime,
    )

    assert passed is False
    assert review_json["passed"] is False
    assert review_json["schema_valid"] is False
    assert review_json["repair_attempts"] == 2
    assert review_json["issues"][0]["actionable_by"] == "framework"
    assert "schema_repair_attempt_2" in review_json["raw_response"]
    assert runtime.call_count == 3
    assert "schema" in feedback.lower() or "scores" in feedback.lower()


async def _run_depth_only_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_cls: type[BaseAgentRuntime],
    *,
    cycle: int = 5,
) -> tuple[bool, str, dict, BaseAgentRuntime]:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", runtime_cls)

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

    work_dir = tmp_path / "atomic-depth"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")
    summary_file = work_dir / "summary.md"
    summary_file.write_text("# summary\n\n## 7. 局限性与未覆盖区域\n", encoding="utf-8")
    task_file = work_dir / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    user_prompt = tmp_path / "depth_user.md"
    user_prompt.write_text(
        "advisor_instance_id: {advisor_instance_id}\n"
        "required: {required_score_fields}\n",
        encoding="utf-8",
    )
    (tmp_path / "worker_system.md").write_text("worker checklist\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="global_depth",
        agent_id="advisor-agent",
        role_name="深入性审计",
        re_review_on_cycle=True,
        system_prompt_file="",
        user_prompt_template=str(user_prompt),
        score_fields=DEPTH_SCORE_FIELDS,
        score_thresholds_start=DEPTH_SCORE_THRESHOLDS_START,
        score_thresholds=DEPTH_SCORE_THRESHOLDS,
    )

    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    passed, feedback = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=cycle,
        review_state=review_state,
        advisor_sessions={},
    )

    review_json = json.loads(
        (work_dir / "reviews" / "global" / f"cycle_{cycle:03d}" / "global_depth.json").read_text(
            encoding="utf-8"
        )
    )
    runtime = registry.get("advisor-agent")
    await registry.shutdown_all()
    return passed, feedback, review_json, runtime


def test_global_review_schema_repair_prompt_uses_valid_comma_separated_scores() -> None:
    prompt = GlobalReviewExecutor._build_schema_repair_prompt(
        review_context_hint="summary=`/tmp/summary.md`",
        parse_outcome=GlobalReviewParseOutcome(
            parsed=ParsedReviewResult(passed=False),
            schema_valid=False,
            parser_mode="json",
            repair_reason="missing scores",
            needs_repair=True,
        ),
        required_score_keys=["vuln_pattern_breadth"],
    )

    assert '"vuln_pattern_breadth": 0.0' in prompt
    assert '"target": "symbol-or-file"' in prompt
    assert '"required_action": "具体动作"' in prompt
    assert "actionable_by" not in prompt
    assert "blocking_type" not in prompt
    assert "acceptance_criteria" not in prompt
    assert "code_evidence_depth" not in prompt
    assert "input_coverage" not in prompt


@pytest.mark.asyncio
async def test_global_depth_accepts_role_specific_scores_without_schema_repair(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passed, feedback, review_json, runtime = await _run_depth_only_review(
        monkeypatch,
        tmp_path,
        DepthOnlyScoreRuntime,
    )

    assert passed is True
    assert feedback == ""
    assert review_json["schema_valid"] is True
    assert review_json["repair_attempts"] == 0
    assert set(review_json["scores"]) == {"vuln_pattern_breadth"}
    assert runtime.call_count == 1


@pytest.mark.asyncio
async def test_global_depth_thresholds_ignore_non_owned_extra_scores(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    passed, feedback, review_json, _ = await _run_depth_only_review(
        monkeypatch,
        tmp_path,
        DepthExtraLowCoverageRuntime,
    )

    assert passed is True
    assert feedback == ""
    assert review_json["passed"] is True
    assert review_json["issues"] == []


@pytest.mark.asyncio
async def test_split_global_review_keeps_upstream_resolutions_when_depth_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", SplitGlobalRuntime)

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

    work_dir = tmp_path / "atomic"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")
    summary_file = work_dir / "summary.md"
    summary_file.write_text("# summary\n\n## 7. 局限性与未覆盖区域\n", encoding="utf-8")
    task_file = work_dir / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")

    completeness_user = tmp_path / "global_review_completeness_user.md"
    completeness_user.write_text(
        "advisor_instance_id: {advisor_instance_id}\n"
        "summary file: `{summary_file}`\n"
        "prior: {prior_global_findings}\n",
        encoding="utf-8",
    )
    depth_user = tmp_path / "global_review_depth_user.md"
    depth_user.write_text(
        "advisor_instance_id: {advisor_instance_id}\n"
        "worker system prompt: `{worker_system_prompt_file}`\n"
        "prior: {prior_global_findings}\n",
        encoding="utf-8",
    )
    (tmp_path / "worker_system.md").write_text("worker checklist\n", encoding="utf-8")

    advisors = [
        AdvisorInstanceDef(
            instance_id="global_completeness",
            agent_id="advisor-agent",
            role_name="全面性审计",
            re_review_on_cycle=True,
            system_prompt_file="",
            user_prompt_template=str(completeness_user),
            score_fields=COMPLETENESS_SCORE_FIELDS,
            score_thresholds_start=COMPLETENESS_SCORE_THRESHOLDS_START,
            score_thresholds=COMPLETENESS_SCORE_THRESHOLDS,
        ),
        AdvisorInstanceDef(
            instance_id="global_depth",
            agent_id="advisor-agent",
            role_name="深入性审计",
            re_review_on_cycle=True,
            system_prompt_file="",
            user_prompt_template=str(depth_user),
            score_fields=DEPTH_SCORE_FIELDS,
            score_thresholds_start=DEPTH_SCORE_THRESHOLDS_START,
            score_thresholds=DEPTH_SCORE_THRESHOLDS,
        ),
    ]

    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    review_state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="need used mapping",
        scores={
            "input_coverage": 1.0,
            "export_followthrough": 0.95,
            "used_coverage": 0.7,
            "vuln_pattern_breadth": 0.9,
            "code_evidence_depth": 0.9,
            "limitations_honesty": 0.95,
            "report_completeness": 0.9,
        },
        issues=[
            {
                "id": "CMP-USED-001",
                "category": "used_coverage",
                "target": "USED table",
                "severity": "high",
                "required_action": "补齐 USED 映射",
                "actionable_by": "worker",
            }
        ],
        resolved_issue_ids=[],
    )

    passed, feedback = await executor.execute(
        advisors_cfg=advisors,
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=review_state,
        advisor_sessions={},
    )

    runtime = registry.get("advisor-agent")
    depth_prompt = runtime.messages[-1]
    assert passed is False
    assert "depth" in feedback.lower()
    # 并行执行后，depth advisor 不再看到 completeness 的 prior_global_findings，
    # 但 resolved_issues 仍然在合并阶段正确处理
    recent_issue_ids = [item.get("id") for item in review_state.get_recent_issues(last_n=2)]
    assert "CMP-USED-001" not in recent_issue_ids
    assert "DEP-PATTERN-001" in recent_issue_ids

    depth_review_json = json.loads(
        (work_dir / "reviews" / "global" / "cycle_002" / "global_depth.json").read_text(encoding="utf-8")
    )
    assert depth_review_json["passed"] is False
    assert depth_review_json["issues"][0]["id"] == "DEP-PATTERN-001"

    await registry.shutdown_all()
