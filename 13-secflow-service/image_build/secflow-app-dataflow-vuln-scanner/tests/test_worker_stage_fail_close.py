from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef, FrameworkConfig
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.runner import run_framework_config
from run_vuln_scan import generate_config


class StageFailureRuntime(BaseAgentRuntime):
    fail_stage: str = ""

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
            stage = self._detect_worker_stage(message)
            if self.fail_stage == stage:
                return AgentResponse(
                    content="",
                    error=f"{stage} stage failed",
                    conversation_id=session_id,
                    turn_count=session["turns"],
                    finished=False,
                )

            if stage == "summary" and working_dir is not None:
                work_dir = Path(working_dir)
                results_dir = work_dir / "results"
                results_dir.mkdir(parents=True, exist_ok=True)
                (work_dir / "summary.md").write_text(
                    "# summary\n\n## 5. 漏洞汇总表\n\n| 编号 | 文件 | 漏洞 |\n|---|---|---|\n| 001 | result_001.md | mock vuln |\n",
                    encoding="utf-8",
                )
                (results_dir / "result_001.md").write_text(
                    "# mock result\n",
                    encoding="utf-8",
                )

            return AgentResponse(
                content=f"{stage} ok",
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
                        "feedback": "mock confirmed",
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
                    "feedback": "mock global pass",
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

    @staticmethod
    def _detect_worker_stage(message: str) -> str:
        lower = message.lower()
        if "请整理所有漏洞分析结果" in message:
            return "summary"
        if "系统性自审" in message or "深度自审" in message:
            return "reflect"
        return "worker"

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


class EmptyReflectionRuntime(StageFailureRuntime):
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        session_id, session = self._ensure_session(session_id)
        if self.agent_id == "pi-worker" and self._detect_worker_stage(message) == "reflect":
            return AgentResponse(
                content="",
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
            )
        session["turns"] -= 1
        return await super().send_message(
            message=message,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )


class PartialTurnLimitRuntime(StageFailureRuntime):
    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        session_id, session = self._ensure_session(session_id)
        work_dir = Path(working_dir)
        results_dir = work_dir / "results"
        supporting_dir = work_dir / "supporting_docs"
        results_dir.mkdir(parents=True, exist_ok=True)
        supporting_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "result_002.md").write_text(
            "# partial result\n\nEvidence written before turn-limit stop.\n",
            encoding="utf-8",
        )
        (supporting_dir / "partial_cycle2.md").write_text(
            "# partial support\n",
            encoding="utf-8",
        )
        return AgentResponse(
            content="partial files written",
            error="runtime internal turn limit exceeded: 71>70",
            error_code="runtime_turn_limit",
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=False,
            metadata={"status": "runtime_turn_limit"},
        )


@pytest.mark.asyncio
async def test_worker_turn_limit_with_artifact_changes_is_salvaged(tmp_path: Path) -> None:
    system_prompt = tmp_path / "worker_system.md"
    user_prompt = tmp_path / "worker_user.md"
    summary_prompt = tmp_path / "summary.md"
    system_prompt.write_text("system", encoding="utf-8")
    user_prompt.write_text("user {{ task }}", encoding="utf-8")
    summary_prompt.write_text("请整理所有漏洞分析结果", encoding="utf-8")

    wf_def = AtomicWorkflowDef.model_validate(
        {
            "id": "vuln_scan",
            "name": "test",
            "working_dir_template": "vuln_scan_{task_id}",
            "engine": {
                "review_profile": "balanced",
                "max_worker_turns_per_cycle": 70,
            },
            "roles": {
                "worker": {
                    "agent_id": "pi-worker",
                    "prompts": {
                        "work": {
                            "system_prompt_file": str(system_prompt),
                            "user_prompt_file": str(user_prompt),
                        },
                        "reflection": [],
                        "summary": {"prompt_file": str(summary_prompt)},
                    },
                },
                "advisors": {},
            },
        }
    )

    registry = AgentRuntimeRegistry()
    runtime = PartialTurnLimitRuntime(
        {
            "id": "pi-worker",
            "name": "partial",
            "type": "pi_agent",
            "runtime_config": {},
        }
    )
    registry._instances["pi-worker"] = runtime
    executor = WorkerExecutor(registry, recorder=None)  # type: ignore[arg-type]

    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    task_file = work_dir / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    (results_dir / "result_001.md").write_text("# existing\n", encoding="utf-8")
    review_state = ReviewState()
    review_state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="补齐 active backlog",
        issues=[{
            "id": "ISSUE-1",
            "category": "coverage_gap",
            "target": "foo",
            "required_action": "补齐 foo",
            "actionable_by": "worker",
        }],
    )
    ctx = WorkflowContext(
        workflow_id="vuln_scan",
        task_id="initial_001",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=2,
    )

    response = await executor.execute_worker(wf_def, ctx, review_state)

    assert response.finished is True
    assert response.success is True
    assert response.metadata["partial_salvaged"] is True
    checkpoint = json.loads(
        (work_dir / "_meta" / "checkpoints" / "current_step.json").read_text(encoding="utf-8")
    )
    assert checkpoint["status"] == "partial_salvaged"
    assert (results_dir / "result_002.md").is_file()


@pytest.mark.parametrize(
    ("fail_stage", "expected_previous_state"),
    [
        ("worker", "worker"),
        ("summary", "summary"),
    ],
)
@pytest.mark.asyncio
async def test_worker_stage_failures_fail_close_without_advancing_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fail_stage: str,
    expected_previous_state: str,
) -> None:
    StageFailureRuntime.fail_stage = fail_stage
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", StageFailureRuntime)

    run_dir = tmp_path / f"stage-fail-{fail_stage}"
    input_task = tmp_path / f"task-{fail_stage}.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name=f"stage-fail-{fail_stage}",
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

    state_payload = json.loads((atomic_dir / "_meta" / "state.json").read_text(encoding="utf-8"))
    assert state_payload["current_state"] == "failed"
    assert state_payload["previous_state"] == expected_previous_state

    workflow_payload = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))
    assert workflow_payload["status"] == "failed"
    assert fail_stage in workflow_payload["detail"]["error"]

    assert not (atomic_dir / "_meta" / "abnormal_exit.json").exists()

    if fail_stage == "worker":
        assert not list((atomic_dir / "reviews").rglob("*.json"))
    if fail_stage == "worker":
        assert not list((atomic_dir / "_meta" / "reflections").glob("*.json"))
        assert not (atomic_dir / "summary.md").exists()
    if fail_stage == "summary":
        assert not list((atomic_dir / "reviews").rglob("*.json"))


@pytest.mark.asyncio
async def test_reflection_stage_failure_is_non_blocking_and_summary_continues(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    StageFailureRuntime.fail_stage = "reflect"
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", StageFailureRuntime)

    run_dir = tmp_path / "reflect-soft-fail"
    input_task = tmp_path / "task-reflect-soft-fail.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="reflect-soft-fail",
        model="mock-model",
        provider="mock-provider",
        max_cycles=1,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=1,
        review_profile="fast",
    )
    engine = config_payload["workflows"]["atomic"][0]["engine"]
    engine["reflection_passes_per_cycle"] = 1
    config = FrameworkConfig.model_validate(config_payload)
    artifacts = await run_framework_config(config)

    assert artifacts.result.success is True

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    workflow_payload = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))
    assert workflow_payload["status"] == "completed"
    assert (atomic_dir / "summary.md").exists()

    reflection_records = list((atomic_dir / "_meta" / "reflections").glob("*.json"))
    assert len(reflection_records) == 1
    reflection_payload = json.loads(reflection_records[0].read_text(encoding="utf-8"))
    assert reflection_payload["response"].startswith("[WARN]")
    assert "reflect stage failed" in reflection_payload["response"]


@pytest.mark.asyncio
async def test_empty_reflection_response_is_non_blocking_and_summary_continues(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    StageFailureRuntime.fail_stage = ""
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "pi_agent", EmptyReflectionRuntime)

    run_dir = tmp_path / "empty-reflect"
    input_task = tmp_path / "task-empty-reflect.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(input_task),
        run_name="empty-reflect",
        model="mock-model",
        provider="mock-provider",
        max_cycles=1,
        worker_timeout=30,
        advisor_timeout=30,
        thinking="low",
        result_review_concurrency=1,
        review_profile="fast",
    )
    engine = config_payload["workflows"]["atomic"][0]["engine"]
    engine["reflection_passes_per_cycle"] = 1
    config = FrameworkConfig.model_validate(config_payload)
    artifacts = await run_framework_config(config)

    assert artifacts.result.success is True

    atomic_dir = (
        Path(config.global_config.workspace_root)
        / f"pipeline_{config.execution.execution_id}"
        / "stage_01_vuln_scan"
        / "vuln_scan_initial_001"
    )
    workflow_payload = json.loads((atomic_dir / "_meta" / "workflow_result.json").read_text(encoding="utf-8"))
    assert workflow_payload["status"] == "completed"
    assert (atomic_dir / "summary.md").exists()

    reflection_records = list((atomic_dir / "_meta" / "reflections").glob("*.json"))
    assert len(reflection_records) == 1
    reflection_payload = json.loads(reflection_records[0].read_text(encoding="utf-8"))
    assert reflection_payload["response"].startswith("[WARN]")
    assert "返回空响应" in reflection_payload["response"]
