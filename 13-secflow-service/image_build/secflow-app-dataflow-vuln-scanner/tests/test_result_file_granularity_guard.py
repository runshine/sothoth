from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class MultiFindingResultRuntime(BaseAgentRuntime):
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

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        session_id, session = self._ensure_session(session_id)

        if self.agent_id == "pi-worker":
            if "请整理所有漏洞分析结果" in message and working_dir is not None:
                work_dir = Path(working_dir)
                results_dir = work_dir / "results"
                results_dir.mkdir(parents=True, exist_ok=True)
                (work_dir / "summary.md").write_text(
                    "# summary\n\n"
                    "## 5. 漏洞汇总表\n\n"
                    "| 编号 | 文件 | 漏洞 |\n"
                    "|---|---|---|\n"
                    "| 001 | result_001.md | bundled vulns |\n",
                    encoding="utf-8",
                )
                (results_dir / "result_001.md").write_text(
                    "# Vulnerability bundle\n\n"
                    "## VULN-001: First issue\n\nDetails.\n\n"
                    "## VULN-002: Second issue\n\nDetails.\n",
                    encoding="utf-8",
                )
                return AgentResponse(
                    content="summary ok",
                    conversation_id=session_id,
                    turn_count=session["turns"],
                    finished=True,
                )

            return AgentResponse(
                content="worker ok",
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
            )

        if "待验证的漏洞报告" in message:
            return AgentResponse(
                content=json.dumps(
                    {
                        "passed": True,
                        "verdict": "CONFIRMED",
                        "feedback": "advisor would confirm if framework allowed it",
                        "scores": {"issue_truth": 0.95},
                        "confidence": 0.95,
                    },
                    ensure_ascii=False,
                ),
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
            )

        return AgentResponse(
            content=json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "global pass",
                    "scores": {
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


@pytest.mark.asyncio
async def test_result_review_fails_closed_on_multi_finding_result_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", MultiFindingResultRuntime)

    run_dir = tmp_path / "multi-finding-run"
    input_task = tmp_path / "task.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="multi-finding",
        model="mock-model",
        provider="mock-provider",
        max_cycles=1,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=1,
    )
    config = FrameworkConfig.model_validate(config_payload)
    artifacts = await run_framework_config(config)

    assert artifacts.result.success is False

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )

    precheck_path = atomic_dir / "reviews" / "results" / "result_001" / "cycle_001" / "framework_result_shape.json"
    assert precheck_path.exists()
    precheck_payload = json.loads(precheck_path.read_text(encoding="utf-8"))
    assert precheck_payload["passed"] is False
    assert precheck_payload["parser_mode"] == "framework_precheck"
    assert "多个独立漏洞条目" in precheck_payload["feedback_detail"]

    advisor_review_path = atomic_dir / "reviews" / "results" / "result_001" / "cycle_001" / "result_fp_check.json"
    assert not advisor_review_path.exists()

    review_summary = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_001.json").read_text(encoding="utf-8"))
    assert review_summary["result_review"]["passed_count"] == 0
    assert review_summary["result_review"]["failed_count"] == 1
    assert review_summary["result_review"]["failed_files"][0]["filename"] == "result_001.md"
