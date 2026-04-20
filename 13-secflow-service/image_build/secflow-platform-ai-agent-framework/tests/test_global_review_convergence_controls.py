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
            "packet_path": "",
            "results_manifest_path": "",
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
            return json.dumps({"passed": True, "verdict": "TRUE_POSITIVE", "feedback": "ok"}, ensure_ascii=False)

        if "评审入口文件" in message or "review packet" in message.lower() or "当前轮次" in message:
            state["global_prompt_len"] = len(message)
            state["summary_token_in_prompt"] = "HUGE_SUMMARY_TOKEN" in message
            packet_match = re.search(r"review packet: `([^`]+)`", message)
            manifest_match = re.search(r"results manifest: `([^`]+)`", message)
            if packet_match:
                state["packet_path"] = packet_match.group(1)
            if manifest_match:
                state["results_manifest_path"] = manifest_match.group(1)
            return json.dumps({"passed": True, "verdict": "PASS", "feedback": "packet review ok"}, ensure_ascii=False)

        return json.dumps({"passed": True, "verdict": "PASS", "feedback": "default pass"}, ensure_ascii=False)


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
                    {"passed": True, "verdict": "TRUE_POSITIVE", "feedback": "result_001 pass"},
                    ensure_ascii=False,
                )
            state["result_002_reviews"] += 1
            if state["result_002_reviews"] == 1:
                return json.dumps(
                    {"passed": False, "verdict": "UNVERIFIED", "feedback": "证据不足，需要重写"},
                    ensure_ascii=False,
                )
            return json.dumps(
                {"passed": True, "verdict": "TRUE_POSITIVE", "feedback": "result_002 fixed"},
                ensure_ascii=False,
            )

        if "评审入口文件" in message or "当前轮次" in message:
            return json.dumps(
                {
                    "passed": False,
                    "verdict": "FAIL",
                    "feedback": "全局覆盖仍未通过",
                    "scores": {"export_followthrough": 0.70},
                    "blocking_issues": [
                        {
                            "id": "export-followthrough:send-socket",
                            "category": "export_followthrough",
                            "target": "IPSEC_SOCK_SendToSocket",
                            "severity": "high",
                            "required_action": "继续跟入 send socket 链",
                        }
                    ],
                },
                ensure_ascii=False,
            )

        return json.dumps({"passed": True, "verdict": "PASS", "feedback": "default pass"}, ensure_ascii=False)


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
                {"passed": True, "verdict": "TRUE_POSITIVE", "feedback": "stable result pass"},
                ensure_ascii=False,
            )

        if "评审入口文件" in message or "当前轮次" in message:
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

        return json.dumps({"passed": True, "verdict": "PASS", "feedback": "default pass"}, ensure_ascii=False)


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
async def test_global_review_uses_review_packet_and_keeps_prompt_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, artifacts, state = await _run_with_runtime(
        monkeypatch,
        tmp_path,
        PacketAwareRuntime,
        run_name="packet-bounded",
        max_cycles=2,
    )

    assert artifacts.result.success is True
    assert state["summary_size"] > 50000
    assert state["global_prompt_len"] < 8000
    assert state["global_prompt_len"] < state["summary_size"]
    assert state["summary_token_in_prompt"] is False

    packet_path = Path(state["packet_path"])
    assert packet_path.exists()
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["summary_file"].endswith("summary.md")
    assert Path(packet["results_manifest_file"]).exists()
    assert Path(state["results_manifest_path"]).exists()


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
    assert cycle_001["result_review"]["failed_files"][0]["filename"] == "result_002.md"

    assert cycle_002["outcome"] == "global_failed"
    assert sorted(cycle_002["result_review"]["passed_files"]) == ["result_001.md", "result_002.md"]

    assert state["result_review_calls"] == [
        "result_001.md",
        "result_002.md",
        "result_002.md",
    ]
    assert any("result_001.md" in msg and "已通过评审的结果" in msg for msg in state["worker_messages"])


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
    assert "停滞" in (workflow_result["detail"].get("error") or "")
    assert workflow_result["detail"]["cycles_used"] < 6

    cycle_003 = json.loads((atomic_dir / "_meta" / "review_summaries" / "cycle_003.json").read_text(encoding="utf-8"))
    cycle_004_metrics = json.loads((atomic_dir / "_meta" / "cycle_metrics" / "cycle_004.json").read_text(encoding="utf-8"))

    assert cycle_003["workflow_mode"] == "closure"
    assert cycle_004_metrics["plateau_status"]["abort"] is True
    assert state["closure_prompt_seen"] is True
