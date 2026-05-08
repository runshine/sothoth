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


class DirectPromptRuntime(BaseAgentRuntime):
    scenario_state: dict[str, dict] = {}

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        seq = getattr(self, "_session_seq", 0) + 1
        self._session_seq = seq
        session_id = f"session_{self.agent_id}_{seq}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    @classmethod
    def _state_key(cls, working_dir: Optional[str]) -> str:
        return str(Path(working_dir or ".").resolve())

    @classmethod
    def _state_for(cls, working_dir: Optional[str]) -> dict:
        key = cls._state_key(working_dir)
        return cls.scenario_state.setdefault(
            key,
            {
                "worker_calls": [],
                "result_review_calls": [],
                "global_review_calls": [],
                "summary_size": 0,
            },
        )

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
        state = self._state_for(working_dir)

        content = self._route_message(
            message=message,
            session_id=session_id,
            working_dir=working_dir,
            state=state,
        )

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    def _route_message(
        self,
        *,
        message: str,
        session_id: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        if self.agent_id == "pi-worker":
            return self._handle_worker_message(message, session_id, working_dir, state)
        return self._handle_advisor_message(message, working_dir, state)

    @staticmethod
    def _extract_cycle(message: str, session_id: str) -> int:
        for pattern in (r"当前轮次[:：]\s*第?\s*(\d+)", r"# 第\s*(\d+)\s*轮"):
            match = re.search(pattern, message)
            if match:
                return int(match.group(1))
        match = re.search(r"Cycle\s*(\d+)", message)
        if match:
            return int(match.group(1))
        match = re.search(r"worker_cycle_(\d+)", session_id)
        if match:
            return int(match.group(1))
        match = re.search(r"_(\d+)$", session_id)
        return int(match.group(1)) if match else 0

    def _handle_worker_message(
        self,
        message: str,
        session_id: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        cycle = self._extract_cycle(message, session_id)

        if "请整理所有漏洞分析结果" in message:
            huge_chunk = "HUGE_SUMMARY_TOKEN " * 4000
            summary_text = (
                f"# summary cycle {cycle}\n\n"
                "## 5. 漏洞汇总表\n\n"
                "| 编号 | 文件 | 漏洞 |\n"
                "|---|---|---|\n"
                "| 001 | result_001.md | mock vuln |\n\n"
                + huge_chunk
            )
            (work_dir / "summary.md").write_text(summary_text, encoding="utf-8")
            (results_dir / "result_001.md").write_text(
                "# result 001\n\n" + ("HUGE_RESULT_TOKEN " * 3000),
                encoding="utf-8",
            )
            state["summary_size"] = len(summary_text)
            stage = "summary"
            content = "summary generated"
        elif "系统性自审" in message or "深度自审" in message or "自审清单" in message or "自审范围" in message:
            stage = "reflection"
            content = "reflection ok"
        else:
            stage = "worker"
            content = "worker ok"

        state["worker_calls"].append(
            {
                "stage": stage,
                "cycle": cycle,
                "session_id": session_id,
                "prompt_len": len(message),
                "task_token_in_prompt": "HUGE_TASK_TOKEN" in message,
            }
        )
        return content

    def _handle_advisor_message(
        self,
        message: str,
        working_dir: Optional[str],
        state: dict,
    ) -> str:
        if "真实性验证" in message or "请对以下漏洞报告" in message:
            result_file_match = re.search(r"(?:待验证报告|result file): `([^`]+)`", message)
            state["result_review_calls"].append(
                {
                    "prompt_len": len(message),
                    "result_token_in_prompt": "HUGE_RESULT_TOKEN" in message,
                    "result_file": result_file_match.group(1) if result_file_match else "",
                }
            )
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "CONFIRMED",
                    "feedback": "result pass",
                    "scores": {"issue_truth": 0.9},
                    "confidence": 0.9,
                },
                ensure_ascii=False,
            )

        summary_file_match = re.search(r"summary file: `([^`]+)`", message)
        manifest_match = re.search(r"result relations manifest: `([^`]+)`", message)
        state["global_review_calls"].append(
            {
                "prompt_len": len(message),
                "summary_token_in_prompt": "HUGE_SUMMARY_TOKEN" in message,
                "summary_file": summary_file_match.group(1) if summary_file_match else "",
                "result_relations_manifest_file": manifest_match.group(1) if manifest_match else "",
            }
        )
        cycle = len(state["global_review_calls"])
        if cycle == 1:
            return json.dumps(
                {
                    "passed": False,
                    "verdict": "FAIL",
                    "feedback": "需要继续跟入 EXPORT 链",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 0.5,
                        "used_coverage": 1.0,
                        "vuln_pattern_breadth": 0.9,
                        "code_evidence_depth": 0.9,
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
                            "required_action": "继续跟入 send socket 链直到形成可复核结论",
                            "actionable_by": "worker",
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
                "feedback": "issue 已关闭",
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
                "resolved_issues": ["export-followthrough:send-socket"],
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
async def test_worker_and_reviews_use_direct_prompt_mode_and_worker_resets_session_between_cycles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    DirectPromptRuntime.scenario_state.clear()
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", DirectPromptRuntime)

    run_dir = tmp_path / "direct-mode-run"
    huge_task = "# Test Task\n\n" + ("HUGE_TASK_TOKEN " * 3000)
    input_task = tmp_path / "task.md"
    input_task.write_text(huge_task, encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="direct-mode",
        model="mock-model",
        provider="mock-provider",
        max_cycles=2,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=2,
    )
    config = FrameworkConfig.model_validate(config_payload)
    artifacts = await run_framework_config(config)

    assert artifacts.result.success is True

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    state = DirectPromptRuntime.scenario_state[str(atomic_dir.resolve())]

    worker_calls = state["worker_calls"]
    assert len(worker_calls) == 5
    assert all(call["task_token_in_prompt"] is False for call in worker_calls)

    by_cycle: dict[int, dict[str, str]] = {}
    for call in worker_calls:
        by_cycle.setdefault(call["cycle"], {})[call["stage"]] = call["session_id"]

    assert set(by_cycle.keys()) == {1, 2}
    assert set(by_cycle[1].keys()) == {"worker", "reflection", "summary"}
    assert set(by_cycle[2].keys()) == {"worker", "summary"}
    # 单 session 模式：同一 cycle 内各阶段共用同一 session
    assert len(set(by_cycle[1].values())) == 1
    assert len(set(by_cycle[2].values())) == 1
    # 新设计：Worker 跨所有 cycle 复用同一个 session / rpc 进程，保持完整上下文。
    assert next(iter(set(by_cycle[1].values()))) == next(iter(set(by_cycle[2].values())))

    result_review_calls = state["result_review_calls"]
    assert result_review_calls
    assert all(call["result_token_in_prompt"] is False for call in result_review_calls)
    assert all(Path(call["result_file"]).exists() for call in result_review_calls if call["result_file"])

    global_review_calls = state["global_review_calls"]
    assert len(global_review_calls) == 4  # 2 advisors × 2 cycles (parallel execution)
    assert state["summary_size"] > 50000
    assert all(call["prompt_len"] < state["summary_size"] for call in global_review_calls)
    assert all(call["summary_token_in_prompt"] is False for call in global_review_calls)
    assert Path(global_review_calls[0]["summary_file"]).exists()
    assert Path(global_review_calls[0]["result_relations_manifest_file"]).exists()
