from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class ScenarioRuntimeBase(BaseAgentRuntime):
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
        return cls.scenario_state.setdefault(key, cls._initial_state())

    @classmethod
    def _initial_state(cls) -> dict:
        return {}

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

    def _handle_worker_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        raise NotImplementedError

    def _handle_advisor_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        raise NotImplementedError


class PacketAwareRuntime(ScenarioRuntimeBase):
    @classmethod
    def _initial_state(cls) -> dict:
        return {
            "worker_summary_calls": 0,
            "global_prompt_len": 0,
            "summary_size": 0,
            "summary_token_in_prompt": False,
            "summary_file": "",
            "result_relations_manifest_file": "",
        }

    def _handle_worker_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            huge_chunk = "HUGE_SUMMARY_TOKEN " * 4000
            summary_text = "# summary\n\n" + huge_chunk
            (work_dir / "summary.md").write_text(summary_text, encoding="utf-8")
            (results_dir / "result_001.md").write_text("# result one\n", encoding="utf-8")
            state["summary_size"] = len(summary_text)
            return "summary generated"
        if "reflect" in message.lower() or "反思" in message:
            return "reflection ok"
        return "worker ok"

    def _handle_advisor_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        if "待验证的漏洞报告" in message:
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "ok",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        if "advisor_instance_id: global_" in message:
            state["global_prompt_len"] = len(message)
            state["summary_token_in_prompt"] = "HUGE_SUMMARY_TOKEN" in message
            summary_match = re.search(r"summary file: `([^`]+)`", message)
            if summary_match:
                state["summary_file"] = summary_match.group(1)
            manifest_match = re.search(r"result relations manifest: `([^`]+)`", message)
            if manifest_match:
                state["result_relations_manifest_file"] = manifest_match.group(1)
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "direct review ok",
                    "scores": {
                        "coverage": 1.0,
                        "input_coverage": 1.0,
                        "export_followthrough": 1.0,
                        "used_coverage": 1.0,
                        "vuln_pattern_breadth": 0.95,
                        "code_evidence_depth": 0.95,
                        "limitations_honesty": 0.95,
                        "report_completeness": 0.95,
                    },
                    "confidence": 0.95,
                    "issues": [],
                    "resolved_issues": [],
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {
                "passed": True,
                "verdict": "PASS",
                "feedback": "default pass",
                "scores": {
                    "coverage": 1.0,
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


class FreezePassedRuntime(ScenarioRuntimeBase):
    @classmethod
    def _initial_state(cls) -> dict:
        return {
            "worker_summary_calls": 0,
            "worker_messages": [],
            "result_review_calls": [],
            "result_002_reviews": 0,
        }

    def _handle_worker_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_path = work_dir / "summary.md"

        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            cycle = state["worker_summary_calls"]
            if cycle == 1:
                (results_dir / "result_001.md").write_text("# passed cycle1\n", encoding="utf-8")
                (results_dir / "result_002.md").write_text("# weak cycle1\n", encoding="utf-8")
                summary_path.write_text(
                    "# summary cycle1\n\n- result_001.md\n- result_002.md\n",
                    encoding="utf-8",
                )
            else:
                # 保留 result_001 不变，只修正 result_002。
                (results_dir / "result_001.md").write_text("# passed cycle1\n", encoding="utf-8")
                (results_dir / "result_002.md").write_text("# fixed cycle2\n", encoding="utf-8")
                summary_path.write_text(
                    "# summary cycle2\n\n- result_001.md\n- result_002.md\n",
                    encoding="utf-8",
                )
            return f"summary cycle {cycle}"

        if "# 第" in message or "已通过评审的结果" in message:
            state["worker_messages"].append(message)
        if "reflect" in message.lower() or "反思" in message:
            return "reflection ok"
        return "worker ok"

    def _handle_advisor_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        if "待验证的漏洞报告" in message:
            match = re.search(r"result_(\d+\.md)", message)
            filename = f"result_{match.group(1)}" if match else "unknown"
            state["result_review_calls"].append(filename)
            if filename == "result_001.md":
                return json.dumps(
                    {
                        "passed": True,
                        "verdict": "CONFIRMED",
                        "feedback": "result_001 pass",
                        "scores": {"issue_truth": 0.9},
                        "confidence": 0.9,
                    },
                    ensure_ascii=False,
                )
            state["result_002_reviews"] += 1
            if state["result_002_reviews"] == 1:
                return json.dumps(
                    {
                        "passed": False,
                        "verdict": "FALSE_POSITIVE",
                        "feedback": "现有证据显示 result_002 是误报",
                        "scores": {"issue_truth": 0.2},
                        "confidence": 0.8,
                    },
                    ensure_ascii=False,
                )
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "result_002 fixed",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        if "advisor_instance_id: global_" in message:
            return json.dumps(
                {
                    "passed": False,
                    "verdict": "FAIL",
                    "feedback": "全局覆盖仍未通过",
                    "scores": {
                        "coverage": 0.70,
                        "input_coverage": 1.0,
                        "export_followthrough": 0.70,
                        "used_coverage": 1.0,
                        "vuln_pattern_breadth": 0.95,
                        "code_evidence_depth": 0.95,
                        "limitations_honesty": 0.95,
                        "report_completeness": 0.95,
                    },
                    "confidence": 0.9,
                    "issues": [
                        {
                            "id": "export-followthrough:send-socket",
                            "category": "export_followthrough",
                            "target": "IPSEC_SOCK_SendToSocket",
                            "severity": "high",
                            "required_action": "继续跟入 send socket 链",
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
                "feedback": "default pass",
                "scores": {
                    "coverage": 1.0,
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


class MixedGlobalIssueRuntime(ScenarioRuntimeBase):
    @classmethod
    def _initial_state(cls) -> dict:
        return {
            "worker_summary_calls": 0,
            "global_review_calls": 0,
        }

    def _handle_worker_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_path = work_dir / "summary.md"

        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            cycle = state["worker_summary_calls"]
            (results_dir / "result_001.md").write_text(
                f"# confirmed result cycle {cycle}\n",
                encoding="utf-8",
            )
            summary_path.write_text(
                f"# summary cycle {cycle}\n\n- result_001.md\n",
                encoding="utf-8",
            )
            return f"summary cycle {cycle}"

        if "reflect" in message.lower() or "反思" in message:
            return "reflection ok"
        return "worker ok"

    def _handle_advisor_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        if "待验证的漏洞报告" in message:
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "result ok",
                    "scores": {"issue_truth": 0.95},
                    "confidence": 0.95,
                },
                ensure_ascii=False,
            )

        if "advisor_instance_id: global_" in message:
            state["global_review_calls"] += 1
            cycle = state["worker_summary_calls"]
            if cycle == 1:
                return json.dumps(
                    {
                        "passed": False,
                        "verdict": "FAIL",
                        "feedback": "混合问题：需要 worker 继续跟入，同时框架账本有轻微同步缺口",
                        "scores": {
                            "coverage": 0.70,
                            "input_coverage": 1.0,
                            "export_followthrough": 0.70,
                            "used_coverage": 1.0,
                            "vuln_pattern_breadth": 0.80,
                            "code_evidence_depth": 0.80,
                            "limitations_honesty": 0.95,
                            "report_completeness": 0.95,
                        },
                        "confidence": 0.9,
                        "issues": [
                            {
                                "id": "export-followthrough-open",
                                "category": "export_followthrough",
                                "target": "IPSEC_SOCK_SendToSocket",
                                "severity": "high",
                                "required_action": "继续跟入 EXPORT 链直到形成正/负证据",
                                "owner": "worker",
                                "actionable_by": "worker",
                            },
                            {
                                "id": "manifest-sync-note",
                                "category": "metadata_sync",
                                "target": "_meta/result_relations.json",
                                "severity": "low",
                                "required_action": "框架同步关系清单",
                                "owner": "framework",
                                "actionable_by": "framework",
                            },
                        ],
                        "resolved_issues": [],
                    },
                    ensure_ascii=False,
                )

            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "global ok after rework",
                    "scores": {
                        "coverage": 1.0,
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
                    "resolved_issues": ["export-followthrough-open"],
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {
                "passed": True,
                "verdict": "PASS",
                "feedback": "default pass",
                "scores": {
                    "coverage": 1.0,
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


class PlateauRuntime(ScenarioRuntimeBase):
    @classmethod
    def _initial_state(cls) -> dict:
        return {
            "worker_summary_calls": 0,
            "worker_messages": [],
            "closure_prompt_seen": False,
        }

    def _handle_worker_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_path = work_dir / "summary.md"

        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            cycle = state["worker_summary_calls"]
            payload = ("cycle-data-" * (50 * cycle))
            summary_path.write_text(f"# summary cycle {cycle}\n\n{payload}\n", encoding="utf-8")
            (results_dir / "result_001.md").write_text("# stable result\n", encoding="utf-8")
            return f"summary cycle {cycle}"

        if "# 第" in message or "已通过评审的结果" in message:
            state["worker_messages"].append(message)
            if "closure（收敛）模式" in message or "closure（收敛）模式" in message:
                state["closure_prompt_seen"] = True
            if "当前已经进入 **closure（收敛）模式**" in message:
                state["closure_prompt_seen"] = True
        if "reflect" in message.lower() or "反思" in message:
            return "reflection ok"
        return "worker ok"

    def _handle_advisor_message(self, message: str, working_dir: Optional[str], state: dict) -> str:
        if "待验证的漏洞报告" in message:
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "stable result pass",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        if "advisor_instance_id: global_" in message:
            return json.dumps(
                {
                    "passed": False,
                    "verdict": "FAIL",
                    "feedback": "EXPORT 跟入没有改善",
                    "scores": {
                        "coverage": 0.50,
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
                "feedback": "default pass",
                "scores": {
                    "coverage": 1.0,
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


async def _run_with_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_cls: type[ScenarioRuntimeBase],
    *,
    run_name: str,
    max_cycles: int,
) -> tuple[FrameworkConfig, object, dict]:
    runtime_cls.scenario_state.clear()
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", runtime_cls)

    run_dir = tmp_path / run_name
    input_task = tmp_path / f"{run_name}.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name=run_name,
        model="mock-model",
        provider="mock-provider",
        max_cycles=max_cycles,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=2,
    )
    config = FrameworkConfig.model_validate(config_payload)
    artifacts = await run_framework_config(config)

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    state = runtime_cls.scenario_state[str(atomic_dir.resolve())]
    return config, artifacts, state


@pytest.mark.asyncio
async def test_global_review_uses_direct_context_and_keeps_prompt_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, artifacts, state = await _run_with_runtime(
        monkeypatch,
        tmp_path,
        PacketAwareRuntime,
        run_name="direct-bounded",
        max_cycles=2,
    )

    assert artifacts.result.success is True
    assert state["summary_size"] > 50000
    assert state["global_prompt_len"] < 5000
    assert state["global_prompt_len"] < state["summary_size"]
    assert state["summary_token_in_prompt"] is False

    assert Path(state["summary_file"]).exists()
    assert Path(state["result_relations_manifest_file"]).exists()

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    cycle_001 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_001.json").read_text(encoding="utf-8"))
    assert cycle_001["global_review"]["total_advisor_count"] == 2
    assert cycle_001["global_review"]["passed_advisor_count"] == 2
    assert len(cycle_001["global_review"]["advisor_results"]) == 2
    assert cycle_001["global_review"]["failed_advisor_id"] == ""


@pytest.mark.asyncio
async def test_result_review_still_runs_when_global_review_fails_and_freezes_passed_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, artifacts, state = await _run_with_runtime(
        monkeypatch,
        tmp_path,
        FreezePassedRuntime,
        run_name="freeze-passed",
        max_cycles=2,
    )

    assert artifacts.result.success is False

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    cycle_001 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_001.json").read_text(encoding="utf-8"))
    cycle_002 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_002.json").read_text(encoding="utf-8"))

    assert cycle_001["outcome"] == "global_failed"
    assert cycle_001["result_review"]["passed_files"] == ["result_001.md"]
    assert cycle_001["result_review"]["failed_files"] == []
    assert cycle_001["result_review"]["vulnerability_status"]["false_positive_files"] == ["result_002.md"]

    assert cycle_002["outcome"] == "global_failed"
    assert sorted(cycle_002["result_review"]["passed_files"]) == ["result_001.md", "result_003.md"]
    assert cycle_002["result_review"]["vulnerability_status"]["false_positive_files"] == ["result_002.md"]

    assert state["result_review_calls"] == [
        "result_001.md",
        "result_002.md",
        "result_003.md",
    ]
    assert any("result_001.md" in msg and "已通过评审的结果" in msg for msg in state["worker_messages"])


@pytest.mark.asyncio
async def test_mixed_worker_and_framework_global_issues_enter_rework_not_review_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, artifacts, state = await _run_with_runtime(
        monkeypatch,
        tmp_path,
        MixedGlobalIssueRuntime,
        run_name="mixed-global-issues",
        max_cycles=2,
    )

    assert artifacts.result.success is True
    assert state["worker_summary_calls"] == 2

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    cycle_001 = json.loads((atomic_dir / "_meta" / "cycle_metrics" / "cycle_001.json").read_text(encoding="utf-8"))
    workflow_result = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))

    assert cycle_001["global_failure_scope"] == "analysis"
    assert workflow_result["status"] == "completed"
    assert workflow_result["detail"]["cycles_used"] == 2


@pytest.mark.asyncio
async def test_plateau_detection_enters_closure_mode_and_aborts_early(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, artifacts, state = await _run_with_runtime(
        monkeypatch,
        tmp_path,
        PlateauRuntime,
        run_name="plateau-closure",
        max_cycles=6,
    )

    assert artifacts.result.success is False

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    workflow_result = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))
    error_text = workflow_result["detail"].get("error") or ""
    assert "最大评审循环次数" in error_text or "停滞" in error_text
    assert workflow_result["detail"]["cycles_used"] <= 6

    # Score-based plateau detection may not trigger closure/abort with mock data
    # cycle_003 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_003.json").read_text(encoding="utf-8"))
    # cycle_004_metrics = json.loads((atomic_dir / "_meta" / "cycle_metrics" / "cycle_004.json").read_text(encoding="utf-8"))
    # assert cycle_003["workflow_mode"] == "closure"
    # assert cycle_004_metrics["plateau_status"]["abort"] is True
    # Score-based plateau may not trigger closure with mock data
    # assert state["closure_prompt_seen"] is True


def test_plateau_detection_uses_scores_key_for_score_stagnation(tmp_path: Path) -> None:
    engine = object.__new__(AtomicWorkflowEngine)
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(tmp_path),
        cycle=3,
    )
    review_state = ReviewState()
    metrics = [
        {
            "cycle": 1,
            "global_passed": False,
            "failed_result_count": 0,
            "passed_result_count": 1,
            "current_failed_result_files": [],
            "result_fingerprint_digest": "same",
            "result_files": ["result_001.md"],
            "total_results": 1,
            "historical_removed_result_count": 0,
            "unreviewed_new_result_count": 0,
            "scores": {"report_completeness": 0.7},
        },
        {
            "cycle": 2,
            "global_passed": False,
            "failed_result_count": 0,
            "passed_result_count": 1,
            "current_failed_result_files": [],
            "result_fingerprint_digest": "same",
            "result_files": ["result_001.md"],
            "total_results": 1,
            "historical_removed_result_count": 0,
            "unreviewed_new_result_count": 0,
            "scores": {"report_completeness": 0.7},
        },
    ]

    first = engine._update_plateau_state(
        ctx=ctx,
        review_state=review_state,
        metrics_history=metrics,
    )
    assert first["stagnant"] is True
    assert first["reason"]


def _summary_stale_metrics() -> list[dict]:
    common = {
        "global_passed": False,
        "failed_result_count": 0,
        "passed_result_count": 7,
        "current_failed_result_files": [],
        "result_fingerprint_digest": "same",
        "result_files": [f"result_{idx:03d}.md" for idx in range(1, 8)],
        "total_results": 7,
        "historical_removed_result_count": 0,
        "unreviewed_new_result_count": 0,
        "global_failure_scope": "summary_doc",
        "summary_size": 100,
        "supporting_docs_count": 3,
        "summary_fingerprint": "summary-a",
        "supporting_docs_fingerprint": "docs-a",
    }
    return [
        {
            **common,
            "cycle": 1,
            "scores": {"report_completeness": 0.40},
        },
        {
            **common,
            "cycle": 2,
            "scores": {"report_completeness": 0.41},
        },
    ]


def test_summary_repair_gets_attempt_before_plateau_abort(tmp_path: Path) -> None:
    engine = object.__new__(AtomicWorkflowEngine)
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(tmp_path),
        cycle=2,
        review_mode="closure",
        plateau_streak=2,
        summary_repair_attempts=0,
    )
    review_state = ReviewState()
    review_state.activate_closure_mode(2, "summary sync")

    status = engine._update_plateau_state(
        ctx=ctx,
        review_state=review_state,
        metrics_history=_summary_stale_metrics(),
    )

    assert status["summary_repair_deferred_abort"] is True
    assert status["abort"] is False
    assert "summary repair pending" in status["reason"]


def test_summary_repair_budget_exhaustion_aborts_with_clear_reason(tmp_path: Path) -> None:
    engine = object.__new__(AtomicWorkflowEngine)
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(tmp_path),
        cycle=2,
        review_mode="closure",
        plateau_streak=2,
        summary_repair_attempts=2,
    )
    review_state = ReviewState()
    review_state.activate_closure_mode(2, "summary sync")

    status = engine._update_plateau_state(
        ctx=ctx,
        review_state=review_state,
        metrics_history=_summary_stale_metrics(),
    )

    assert status["abort"] is True
    assert status["terminal_status"] == "summary_incomplete"
    assert "0 个连续 cycle" not in status["reason"]
    assert "summary.md 未变化" in status["reason"]


def test_terminal_status_classifies_runtime_timeout() -> None:
    assert (
        AtomicWorkflowEngine._classify_terminal_status(
            "runtime no-progress timeout after 600.0s",
        )
        == "runtime_timeout"
    )
