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
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class ComplexWorkflowRuntime(BaseAgentRuntime):
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
    def _state_for(cls, working_dir: Optional[str]) -> dict:
        key = str(Path(working_dir or ".").resolve())
        return cls.scenario_state.setdefault(
            key,
            {
                "worker_summary_calls": 0,
                "global_review_calls": 0,
                "result_reviews": [],
            },
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
            content = self._handle_advisor_message(message, state)

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    def _handle_worker_message(
        self,
        message: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        if working_dir is None:
            return "worker: no working dir"

        work_dir = Path(working_dir)
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_path = work_dir / "summary.md"

        if "请整理所有漏洞分析结果" in message:
            state["worker_summary_calls"] += 1
            cycle = state["worker_summary_calls"]

            if cycle == 1:
                (results_dir / "result_001.md").write_text(
                    "# false positive report cycle1\n", encoding="utf-8")
                (results_dir / "result_002.md").write_text(
                    "# passed report cycle1\n", encoding="utf-8")
                summary_path.write_text(
                    "# summary cycle 1\n\n- result_001.md\n- result_002.md\n",
                    encoding="utf-8",
                )
            elif cycle == 2:
                stale = results_dir / "result_001.md"
                if stale.exists():
                    stale.unlink()
                (results_dir / "result_002.md").write_text(
                    "# new report created by overwriting protected file\n",
                    encoding="utf-8",
                )
                (results_dir / "REMOVED.md").write_text(
                    "# removed audit log\n\n- result_001.md removed as false positive\n",
                    encoding="utf-8",
                )
                (results_dir / "USED_ENDPOINTS.md").write_text(
                    "# used endpoints appendix\n\n- endpoint-001 safe\n",
                    encoding="utf-8",
                )
                summary_path.write_text(
                    "# summary cycle 2\n\n- result_002.md\n- REMOVED.md\n- USED_ENDPOINTS.md\n",
                    encoding="utf-8",
                )
            else:
                summary_path.write_text(
                    f"# unexpected summary cycle {cycle}\n", encoding="utf-8")

            return f"worker summary cycle {cycle}"

        if "reflect_completeness" in message or "反思" in message:
            return "worker reflection ok"

        return "worker work ok"

    def _handle_advisor_message(self, message: str, state: dict) -> str:
        if "待验证的漏洞报告" in message:
            match = re.search(r"result_(\d+\.md)", message)
            filename = f"result_{match.group(1)}" if match else "unknown"
            state["result_reviews"].append(filename)
            if filename == "result_001.md":
                return json.dumps(
                    {
                        "passed": False,
                        "verdict": "FALSE_POSITIVE",
                        "feedback": "误报，已从最终结果删除",
                        "scores": {"issue_truth": 0.1},
                        "confidence": 0.9,
                    },
                    ensure_ascii=False,
                )
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": f"{filename} 验证通过",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        if "当前轮次" in message:
            state["global_review_calls"] += 1
            cycle = state["global_review_calls"]
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": f"Cycle {cycle} global review pass",
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
                "feedback": "default advisor pass",
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
async def test_complex_workflow_tracks_false_positive_without_worker_rework(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ComplexWorkflowRuntime.scenario_state.clear()
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", ComplexWorkflowRuntime)

    run_dir = tmp_path / "run"
    input_task = tmp_path / "task.md"
    input_task.write_text("# Complex Test Task\n\nVerify rework robustness.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="complex",
        model="mock-model",
        provider="mock-provider",
        max_cycles=3,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=2,
    )
    config = FrameworkConfig.model_validate(config_payload)

    artifacts = await run_framework_config(config)

    assert artifacts.result.success is True
    assert len(artifacts.result.final_tasks) == 1

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    results_dir = atomic_dir / "results"
    final_output_dir = atomic_dir / "final_output"

    assert sorted(p.name for p in results_dir.glob("result_*.md")) == [
        "result_001.md",
        "result_002.md",
    ]
    assert (results_dir / "result_001.md").read_text(encoding="utf-8") == "# false positive report cycle1\n"
    assert (results_dir / "result_002.md").read_text(encoding="utf-8") == "# passed report cycle1\n"

    assert not (atomic_dir / "removed_results").exists()

    assert sorted(p.name for p in (final_output_dir / "results").glob("result_*.md")) == [
        "result_002.md",
    ]
    assert sorted(p.name for p in (final_output_dir / "false_positive_results").glob("result_*.md")) == [
        "result_001.md",
    ]

    final_output_index = json.loads((final_output_dir / "index.json").read_text(encoding="utf-8"))
    assert "results/result_002.md" in final_output_index["files"]
    assert "false_positive_results/result_001.md" in final_output_index["files"]
    assert final_output_index["vulnerability_status"]["confirmed_files"] == ["result_002.md"]
    assert final_output_index["vulnerability_status"]["false_positive_files"] == ["result_001.md"]

    next_tasks = json.loads((atomic_dir / "output" / "next_tasks.json").read_text(encoding="utf-8"))
    assert [task["id"] for task in next_tasks["tasks"]] == ["result_002"]

    cycle_001 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_001.json").read_text(encoding="utf-8"))
    cycle_001_metrics = json.loads((atomic_dir / "_meta" / "cycle_metrics" / "cycle_001.json").read_text(encoding="utf-8"))
    assert cycle_001["outcome"] == "all_passed"
    assert cycle_001["result_review"]["passed_files"] == ["result_002.md"]
    assert cycle_001["result_review"]["failed_files"] == []
    assert cycle_001["result_review"]["vulnerability_status"]["false_positive_files"] == ["result_001.md"]
    assert cycle_001_metrics["current_failed_result_count"] == 0
    assert cycle_001_metrics["historical_removed_result_count"] == 0
    assert cycle_001_metrics["false_positive_result_count"] == 1
    assert cycle_001_metrics["unreviewed_new_result_count"] == 0

    summary_text = (atomic_dir / "summary.md").read_text(encoding="utf-8")
    assert "result_001.md" in summary_text
    assert "result_002.md" in summary_text
