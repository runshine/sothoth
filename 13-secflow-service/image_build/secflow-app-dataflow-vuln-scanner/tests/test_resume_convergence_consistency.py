from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.resume import build_resume_plan, rebuild_review_state, resume_run
from app.pi_vuln_core.review.state import calculate_file_sha256
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class ResumeConsistencyRuntime(BaseAgentRuntime):
    scenario_state: dict[str, dict] = {}

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"session_{self.agent_id}_{len(self._sessions) + 1}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    def _ensure_session(self, session_id: Optional[str]) -> tuple[str, dict]:
        if session_id is None:
            session_id = f"session_{self.agent_id}_{len(self._sessions) + 1}"
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        return session_id, session

    @classmethod
    def _state_key(cls, working_dir: Optional[str]) -> str:
        return str(Path(working_dir or ".").resolve())

    @classmethod
    def _state_for(cls, working_dir: Optional[str]) -> dict:
        key = cls._state_key(working_dir)
        return cls.scenario_state.setdefault(
            key,
            {
                "worker_summary_calls": 0,
                "global_review_calls": 0,
                "result_review_calls": [],
                "worker_rework_messages": [],
            },
        )

    def _persist_call_trace(
        self,
        *,
        working_dir: Optional[str],
        session_id: str,
        turn_count: int,
        message: str,
        system_prompt: Optional[str],
        response_content: str,
    ) -> None:
        if not working_dir:
            return
        work_dir = Path(working_dir)
        call_dir = (
            work_dir
            / "sessions"
            / session_id
            / "calls"
            / f"{turn_count:03d}_{self.agent_id.replace('-', '_')}"
        )
        call_dir.mkdir(parents=True, exist_ok=True)
        (call_dir / "request.json").write_text(
            json.dumps(
                {
                    "agent_id": self.agent_id,
                    "session_id": session_id,
                    "message_preview": message[:200],
                    "system_prompt_preview": (system_prompt or "")[:200],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        (call_dir / "response.json").write_text(
            json.dumps(
                {
                    "content_preview": response_content[:200],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        session_id, session = self._ensure_session(session_id)
        state = self._state_for(working_dir)

        if self.agent_id == "pi-worker":
            content = self._handle_worker_message(message, working_dir, state)
        else:
            content = self._handle_advisor_message(message, working_dir, state)

        self._persist_call_trace(
            working_dir=working_dir,
            session_id=session_id,
            turn_count=session["turns"],
            message=message,
            system_prompt=system_prompt,
            response_content=content,
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

    def _handle_worker_message(
        self,
        message: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_path = work_dir / "summary.md"

        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            cycle = state["worker_summary_calls"]
            (results_dir / "result_001.md").write_text("# stable passed result\n", encoding="utf-8")
            summary_path.write_text(
                f"# summary cycle {cycle}\n\n- result_001.md\n",
                encoding="utf-8",
            )
            return f"summary cycle {cycle}"

        if "# 第" in message or "已通过评审的结果" in message:
            state["worker_rework_messages"].append(message)
        if "reflect" in message.lower() or "反思" in message:
            return "reflection ok"
        return "worker ok"

    def _handle_advisor_message(
        self,
        message: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        if "待验证的漏洞报告" in message:
            match = re.search(r"result_(\d+\.md)", message)
            filename = f"result_{match.group(1)}" if match else "unknown"
            state["result_review_calls"].append(filename)
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": f"{filename} 通过",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        if "评审入口文件" in message or "当前轮次" in message:
            state["global_review_calls"] += 1
            is_completeness = "advisor_instance_id: global_completeness" in message
            if is_completeness:
                state.setdefault("completeness_review_calls", 0)
                state["completeness_review_calls"] += 1
                if state["completeness_review_calls"] <= 3:
                    return json.dumps(
                        {
                            "passed": False,
                            "verdict": "FAIL",
                            "feedback": "EXPORT 跟入没有改善",
                            "scores": {
                                "input_coverage": 1.0,
                                "export_followthrough": 0.50,
                                "used_coverage": 1.0,
                                "vuln_pattern_breadth": 0.9,
                                "code_evidence_depth": 0.9,
                                "limitations_honesty": 0.95,
                                "report_completeness": 0.80,
                            },
                            "confidence": 0.9,
                            "issues": [
                                {
                                    "id": "export-followthrough:send-socket",
                                    "category": "export_followthrough",
                                    "target": "IPSEC_SOCK_SendToSocket",
                                    "severity": "high",
                                    "required_action": "继续跟入 send socket 链直到形成可复核结论",
                                }
                            ],
                            "resolved_issues": [],
                        },
                        ensure_ascii=False,
                    )
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "所有 issue 已关闭",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 1.0,
                        "used_coverage": 1.0,
                        "vuln_pattern_breadth": 0.95,
                        "code_evidence_depth": 0.95,
                        "limitations_honesty": 0.95,
                        "report_completeness": 1.0,
                    },
                    "confidence": 0.95,
                    "issues": [],
                    "resolved_issues": ["export-followthrough:send-socket"],
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {
                "passed": True,
                "verdict": "PASS",
                "feedback": "default pass",
                "scores": {
                    "input_coverage": 1.0,
                    "export_followthrough": 1.0,
                    "used_coverage": 1.0,
                    "vuln_pattern_breadth": 1.0,
                    "code_evidence_depth": 1.0,
                    "limitations_honesty": 1.0,
                    "report_completeness": 1.0,
                },
                "confidence": 0.99,
                "issues": [],
                "resolved_issues": [],
            },
            ensure_ascii=False,
        )


def test_rebuild_review_state_restores_issues_closure_and_passed_results(tmp_path: Path) -> None:
    atomic_dir = tmp_path / "atomic"
    results_dir = atomic_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# passed\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# failed\n", encoding="utf-8")

    global_cycle_1 = atomic_dir / "reviews" / "global" / "cycle_001"
    global_cycle_2 = atomic_dir / "reviews" / "global" / "cycle_002"
    global_cycle_1.mkdir(parents=True, exist_ok=True)
    global_cycle_2.mkdir(parents=True, exist_ok=True)
    (global_cycle_1 / "global_quality.json").write_text(
        json.dumps(
            {
                "advisor_instance_id": "global_quality",
                "cycle": 1,
                "passed": False,
                "workflow_mode": "discovery",
                "scores": {"export_followthrough": 0.5},
                "feedback_detail": "first fail",
                "issues": [
                    {
                        "id": "export-followthrough:send-socket",
                        "category": "export_followthrough",
                        "target": "IPSEC_SOCK_SendToSocket",
                        "required_action": "继续跟入",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (global_cycle_2 / "global_quality.json").write_text(
        json.dumps(
            {
                "advisor_instance_id": "global_quality",
                "cycle": 2,
                "passed": False,
                "workflow_mode": "closure",
                "scores": {"export_followthrough": 0.5},
                "feedback_detail": "still blocked",
                "issues": [
                    {
                        "id": "export-followthrough:send-socket",
                        "category": "export_followthrough",
                        "target": "IPSEC_SOCK_SendToSocket",
                        "required_action": "继续跟入",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    result_pass_dir = atomic_dir / "reviews" / "results" / "result_001" / "cycle_001"
    result_fail_dir = atomic_dir / "reviews" / "results" / "result_002" / "cycle_002"
    result_pass_dir.mkdir(parents=True, exist_ok=True)
    result_fail_dir.mkdir(parents=True, exist_ok=True)
    (result_pass_dir / "result_fp_check.json").write_text(
        json.dumps(
            {
                "result_file": "result_001.md",
                "cycle": 1,
                "passed": True,
                "feedback_detail": "ok",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (result_fail_dir / "result_fp_check.json").write_text(
        json.dumps(
            {
                "result_file": "result_002.md",
                "cycle": 2,
                "passed": False,
                "feedback_detail": "证据不足",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    state = rebuild_review_state(atomic_dir)

    assert state.workflow_mode == "closure"
    assert state.closure_since_cycle == 2
    recent_issues = state.get_recent_issues(last_n=1)
    assert [item["id"] for item in recent_issues] == ["export-followthrough:send-socket"]
    assert recent_issues[0]["advisor_id"] == "global_quality"
    assert state.last_global_scores["export_followthrough"] == 0.5

    fingerprint = calculate_file_sha256(str(results_dir / "result_001.md"))
    assert state.is_result_passed("result_001.md", fingerprint) is True
    failed_fingerprint = calculate_file_sha256(str(results_dir / "result_002.md"))
    assert state.is_result_failed("result_002.md", failed_fingerprint) is True
    assert state.get_pending_results(
        ["result_002.md"],
        [{"re_review_on_cycle": False}],
        {"result_002.md": failed_fingerprint},
    ) == []
    failed = state.get_failed_results()
    assert len(failed) == 1
    assert failed[0].filename == "result_002.md"
    assert failed[0].reason == "证据不足"


@pytest.mark.asyncio
async def test_resume_run_preserves_issues_closure_and_passed_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ResumeConsistencyRuntime.scenario_state.clear()
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", ResumeConsistencyRuntime)

    run_dir = tmp_path / "resume-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    input_task = tmp_path / "task.md"
    input_task.write_text("# Resume Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="resume-case",
        model="mock-model",
        provider="mock-provider",
        max_cycles=3,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=2,
    )
    (run_dir / "config.json").write_text(
        json.dumps(config_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    from app.pi_vuln_core.config.models import FrameworkConfig

    config = FrameworkConfig.model_validate(config_payload)
    first_artifacts = await run_framework_config(config)
    assert first_artifacts.result.success is False

    _, plan = build_resume_plan(run_dir)
    assert plan.completed_cycles == 3
    rebuilt_state = rebuild_review_state(plan.atomic_work_dir)
    assert rebuilt_state.workflow_mode == "closure"
    assert isinstance(rebuilt_state.get_recent_issues(last_n=1), list)

    resumed_artifacts = await resume_run(run_dir, extra_cycles=1)
    assert resumed_artifacts.result.success is True

    atomic_dir = Path(plan.atomic_work_dir)
    workflow_result = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))
    cycle_003_summary = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_003.json").read_text(encoding="utf-8"))
    cycle_004_summary = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_004.json").read_text(encoding="utf-8"))

    assert workflow_result["status"] == "completed"
    assert workflow_result["detail"]["cycles_used"] == 4
    assert cycle_003_summary["workflow_mode"] == "closure"
    assert cycle_003_summary["global_review"]["failed_advisor_id"] in ("", "global_completeness")
    # failed_role_name may be empty if global review passes in cycle 3
    assert cycle_004_summary["outcome"] == "all_passed"
    assert cycle_004_summary["global_review"]["total_advisor_count"] == 2

    runtime_state = ResumeConsistencyRuntime.scenario_state[str(atomic_dir.resolve())]
    assert runtime_state["result_review_calls"] == ["result_001.md"]
    assert any("当前已经进入 **closure（收敛）模式**" in msg for msg in runtime_state["worker_rework_messages"])
    assert any("result_001.md" in msg and "已通过评审" in msg for msg in runtime_state["worker_rework_messages"])
    # Issue IDs no longer injected into worker messages
    # assert any("export-followthrough:send-socket" in msg for msg in runtime_state["worker_rework_messages"])
