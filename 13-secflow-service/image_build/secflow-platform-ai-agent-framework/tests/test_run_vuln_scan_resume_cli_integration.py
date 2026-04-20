from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Optional

import pytest

import run_vuln_scan
from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class ResumeCliIntegrationRuntime(BaseAgentRuntime):
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
                "global_review_messages": [],
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
                    "message_preview": message[:300],
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
                    "content_preview": response_content[:300],
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
            content = self._handle_advisor_message(message, state)

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

    def _handle_advisor_message(self, message: str, state: dict) -> str:
        if "待验证的漏洞报告" in message:
            match = re.search(r"result_(\d+\.md)", message)
            filename = f"result_{match.group(1)}" if match else "unknown"
            state["result_review_calls"].append(filename)
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "TRUE_POSITIVE",
                    "feedback": f"{filename} 通过",
                },
                ensure_ascii=False,
            )

        if "评审入口文件" in message or "review packet" in message.lower() or "当前轮次" in message:
            state["global_review_calls"] += 1
            state["global_review_messages"].append(message)
            cycle = state["global_review_calls"]
            if cycle <= 3:
                return json.dumps(
                    {
                        "passed": False,
                        "verdict": "FAIL",
                        "feedback": "EXPORT 跟入没有改善",
                        "scores": {
                            "export_followthrough": 0.50,
                            "report_completeness": 0.80,
                        },
                        "blocking_issues": [
                            {
                                "id": "export-followthrough:send-socket",
                                "category": "export_followthrough",
                                "target": "IPSEC_SOCK_SendToSocket",
                                "severity": "high",
                                "required_action": "继续跟入 send socket 链直到形成可复核结论",
                            }
                        ],
                    },
                    ensure_ascii=False,
                )
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "所有 blocker 已关闭",
                    "scores": {
                        "export_followthrough": 1.0,
                        "report_completeness": 1.0,
                    },
                    "resolved_issues": ["export-followthrough:send-socket"],
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {
                "passed": True,
                "verdict": "PASS",
                "feedback": "default pass",
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


def _run_script(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc_info:
        run_vuln_scan.main()
    assert isinstance(exc_info.value.code, int)
    return exc_info.value.code


def test_run_vuln_scan_resume_preview_and_actual_resume_follow_design_logic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ResumeCliIntegrationRuntime.scenario_state.clear()
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", ResumeCliIntegrationRuntime)

    run_dir = tmp_path / "resume-cli-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    input_task = tmp_path / "task.md"
    input_task.write_text("# Resume CLI Test\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="resume-cli-case",
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

    config = FrameworkConfig.model_validate(config_payload)
    first_artifacts = asyncio.run(run_framework_config(config))
    assert first_artifacts.result.success is False

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    state = ResumeCliIntegrationRuntime.scenario_state[str(atomic_dir.resolve())]
    assert state["global_review_calls"] == 3
    assert state["result_review_calls"] == ["result_001.md"]
    assert all("review packet" in msg.lower() for msg in state["global_review_messages"])

    # 先做 dry-run / explain-resume，只输出诊断，不实际继续执行。
    exit_code = _run_script(
        monkeypatch,
        [
            "run_vuln_scan.py",
            "--resume-run-dir",
            str(run_dir),
            "--extra-cycles",
            "1",
            "--dry-run-resume",
        ],
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "当前模式:   closure" in captured.out
    assert "OpenBlockers: 1" in captured.out
    assert "Plateau:" in captured.out
    assert "dry-run-resume" in captured.out
    assert state["global_review_calls"] == 3  # dry-run 不会调用任何 agent

    preview_path = atomic_dir / "_meta" / "resume_preview.json"
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    assert preview["completed_cycles"] == 3
    assert preview["extra_cycles_requested"] == 1
    assert preview["resume_total_cycle_limit"] == 4
    assert preview["diagnostics"]["workflow_mode"] == "closure"
    assert preview["diagnostics"]["open_blocker_count"] == 1
    assert preview["diagnostics"]["blockers_preview"][0].startswith("[export-followthrough:send-socket]")

    # 再做真正的 resume，应在 closure 模式下继续，并最终通过。
    exit_code = _run_script(
        monkeypatch,
        [
            "run_vuln_scan.py",
            "--resume-run-dir",
            str(run_dir),
            "--extra-cycles",
            "1",
        ],
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "轮次窗口:   3 -> 4" in captured.out
    assert "预览文件:" in captured.out
    assert "✅ 漏洞挖掘完成" in captured.out

    assert state["global_review_calls"] == 4
    assert any("当前已经进入 **closure（收敛）模式**" in msg for msg in state["worker_rework_messages"])
    assert any("result_001.md" in msg and "已通过评审的结果" in msg for msg in state["worker_rework_messages"])
    assert any("export-followthrough:send-socket" in msg for msg in state["worker_rework_messages"])

    cycle_004 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_004.json").read_text(encoding="utf-8"))
    assert cycle_004["outcome"] == "all_passed"
    assert cycle_004["workflow_mode"] == "closure"
