from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.checkpoint import load_step_checkpoint
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.template import TemplateRenderError, render_string
from app.pi_vuln_core.agents.models import AgentResponse


def _workflow_with_worker_prompt(
    worker_prompt: Path,
    summary_prompt: Path,
    rework_prompt: Path | None = None,
) -> AtomicWorkflowDef:
    work_prompt = {
        "system_prompt_file": "prompts/vuln_scan/worker_system.md",
        "user_prompt_file": str(worker_prompt),
    }
    if rework_prompt is not None:
        work_prompt["rework_prompt_file"] = str(rework_prompt)
    return AtomicWorkflowDef.model_validate(
        {
            "id": "wf",
            "name": "wf",
            "working_dir_template": "wf_{task_id}",
            "roles": {
                "worker": {
                    "agent_id": "worker",
                    "prompts": {
                        "work": work_prompt,
                        "reflection": [],
                        "summary": {
                            "prompt_file": str(summary_prompt),
                            "output_summary_filename": "summary.md",
                            "output_results_dir": "results",
                        },
                    },
                },
                "advisors": {"global_review": [], "result_review": []},
            },
        }
    )


def test_strict_prompt_rendering_fails_on_missing_template_variables() -> None:
    with pytest.raises(TemplateRenderError, match=r"\{task\}"):
        render_string("Task:\n{task}\nOutput: {summary_path}\n", strict=True, summary_path="/tmp/summary.md")


def test_strict_prompt_rendering_allows_braces_inside_values() -> None:
    rendered = render_string(
        "Task:\n{task}\nOutput: {summary_path}\n",
        strict=True,
        task='code sample: if (x) { return; } and json {"name": "{not_a_template}"}',
        summary_path="/tmp/summary.md",
    )

    assert "{task}" not in rendered
    assert "{not_a_template}" in rendered


def test_jinja_prompt_rendering_uses_framework_error_type() -> None:
    with pytest.raises(TemplateRenderError, match="missing_var"):
        render_string("Task: {{ missing_var }}", strict=True)


def test_worker_system_prompt_stays_stable_without_run_scoped_appendix() -> None:
    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    audit_ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file="task.md",
        working_dir="/tmp/work",
        review_profile="audit",
    )
    balanced_ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file="task.md",
        working_dir="/tmp/work",
        review_profile="balanced",
    )

    audit_prompt = executor._build_worker_system_prompt(
        "prompts/vuln_scan/worker_system.md",
        audit_ctx,
    )
    balanced_prompt = executor._build_worker_system_prompt(
        "prompts/vuln_scan/worker_system.md",
        balanced_ctx,
    )

    assert "## 本轮扩展方法学" not in audit_prompt
    assert "## 漏洞模式补充检查清单" not in audit_prompt
    assert "## result_NNN.md 强制结构摘要" not in audit_prompt
    assert "## 本轮扩展方法学" not in balanced_prompt


def test_worker_user_prompt_receives_audit_appendix_as_runtime_context(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        review_profile="audit",
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        ReviewState(),
    )

    assert "## 本轮扩展方法学" in prompt
    assert "## 漏洞模式补充检查清单" in prompt


def test_worker_user_prompt_skips_audit_appendix_for_custom_system_prompt(tmp_path: Path) -> None:
    custom_system = tmp_path / "worker_system.md"
    custom_system.write_text("custom system\n", encoding="utf-8")
    worker_prompt = tmp_path / "worker_user.md"
    worker_prompt.write_text("{worker_runtime_context}\n{result_report_template}\n", encoding="utf-8")
    summary_prompt = tmp_path / "summary.md"
    summary_prompt.write_text("summary\n", encoding="utf-8")
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    wf = _workflow_with_worker_prompt(worker_prompt, summary_prompt)
    wf.roles.worker.prompts.work.system_prompt_file = str(custom_system)
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        review_profile="audit",
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        ReviewState(),
    )

    assert "## 本轮扩展方法学" not in prompt


def test_pipeline_worker_prompt_receives_task_alias(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# Docker task\n\n- 输入文件夹路径: /firmware\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    wf = _workflow_with_worker_prompt(
        Path("prompts/pipeline/unpack_analysis/worker_user.md"),
        Path("prompts/pipeline/unpack_analysis/summary.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=1,
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        ReviewState(),
    )

    assert "{task}" not in prompt
    assert "输入文件夹路径: /firmware" in prompt
    assert str(work_dir) in prompt


def test_summary_or_ledger_issue_enters_rework_prompt(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    (work_dir / "results").mkdir(parents=True)
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=2,
        review_mode="closure",
        failed_result_items=[],
        plateau_reason="结果评审已通过，剩余问题集中在 summary/ledger 同步",
    )
    state = ReviewState()
    state.workflow_mode = "closure"
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="summary 漏洞汇总表没有同步 supporting docs",
        scores={"report_completeness": 0.6},
        issues=[
            {
                "id": "summary-ledger-sync",
                "category": "report_completeness",
                "target": "summary.md",
                "severity": "high",
                "required_action": "同步 summary.md 与 coverage ledger",
                "actionable_by": "summary",
            }
        ],
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        state,
    )

    assert "第 2 轮评审返工" in prompt
    assert "summary 漏洞汇总表没有同步 supporting docs" in prompt
    assert "本轮主要为 summary/ledger handoff" in prompt
    assert "只补充后续 summary 阶段需要的 `supporting_docs/` 证据" in prompt
    assert "不要新增、删除、重写或重新编号 `results/result_NNN.md`" in prompt


def test_configured_rework_prompt_template_is_used(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text("# old result\n", encoding="utf-8")
    rework_prompt = tmp_path / "worker_rework.md"
    rework_prompt.write_text(
        "REWORK TEMPLATE {cycle}\n"
        "{active_issue_backlog}\n"
        "{failed_result_reasons}\n"
        "{coverage_context}\n",
        encoding="utf-8",
    )
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
        rework_prompt=rework_prompt,
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=2,
        review_mode="discovery",
    )
    state = ReviewState()
    state.mark_result_failed("result_001.md", 1, "needs stronger source evidence")
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="worker gap remains",
        scores={"used_coverage": 0.5},
        issues=[
            {
                "id": "worker-gap",
                "category": "used_coverage",
                "target": "USED endpoint",
                "severity": "medium",
                "required_action": "补齐 USED endpoint 覆盖",
                "actionable_by": "worker",
            }
        ],
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        state,
    )

    assert "REWORK TEMPLATE 2" in prompt
    assert "worker-gap" in prompt
    assert "result_001.md" in prompt
    assert "needs stronger source evidence" in prompt
    assert "Coverage / issue radar" in prompt


def test_default_rework_prompt_is_incremental_for_shared_worker_session(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    meta_dir = work_dir / "_meta"
    results_dir.mkdir(parents=True)
    meta_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text("# passed\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# failed\n", encoding="utf-8")
    (meta_dir / "coverage_ledger.json").write_text(
        json.dumps(
            {
                "coverage_obligations": {
                    "open_entries": [
                        {
                            "id": "USED:danger_len",
                            "kind": "used",
                            "label": "USED",
                            "value": "danger_len@L42",
                            "risk": "high",
                            "status": "open",
                        }
                    ]
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
        rework_prompt=Path("prompts/vuln_scan/worker_rework.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=2,
        review_mode="discovery",
    )
    state = ReviewState()
    state.mark_result_passed("result_001.md", 1)
    state.mark_result_failed("result_002.md", 1, "source check contradicts report")
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="mixed worker and summary issues",
        scores={"used_coverage": 0.5},
        issues=[
            {
                "id": "worker-used-gap",
                "category": "coverage_gap",
                "target": "danger_len",
                "required_action": "补齐 USED sink 证据",
                "actionable_by": "worker",
            },
            {
                "id": "summary-table-sync",
                "category": "report_completeness",
                "target": "summary.md",
                "required_action": "同步 summary 表格",
                "actionable_by": "summary",
            },
        ],
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        state,
    )

    assert "Worker 的所有 cycle 共用同一个 session" in prompt
    assert "本轮增量目标队列" in prompt
    assert "### P0 failed results" in prompt
    assert "### P1 worker active issues" in prompt
    assert "### P2 coverage targets" in prompt
    assert "Summary / Ledger handoff" in prompt
    assert "summary-table-sync" in prompt
    assert "不要求本轮关闭全部 open obligations" in prompt
    assert "只处理失败 result" not in prompt
    assert "不要重新通读所有历史 result/supporting_docs" in prompt


def test_staged_rework_sequence_uses_one_worker_session_and_checkpoints(tmp_path: Path) -> None:
    class FakeWorkerAgent:
        def __init__(self) -> None:
            self.messages: list[dict[str, str]] = []

        async def multi_turn_execute(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
            working_dir: str,
            max_turns: int,
            session_id: str,
        ) -> AgentResponse:
            self.messages.append({
                "kind": "multi_turn",
                "session_id": session_id,
                "message": user_prompt,
                "system_prompt": system_prompt,
            })
            return AgentResponse(
                content="triage ok",
                conversation_id=session_id,
                turn_count=len(self.messages),
                finished=True,
            )

        async def send_message(
            self,
            *,
            message: str,
            session_id: str,
            working_dir: str,
        ) -> AgentResponse:
            self.messages.append({
                "kind": "send_message",
                "session_id": session_id,
                "message": message,
                "system_prompt": "",
            })
            return AgentResponse(
                content="stage ok",
                conversation_id=session_id,
                turn_count=len(self.messages),
                finished=True,
            )

    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text("# failed\n", encoding="utf-8")
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
        rework_prompt=Path("prompts/vuln_scan/worker_rework.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=2,
        review_mode="discovery",
        worker_session_id="worker-session-1",
        worker_session_cycle=2,
    )
    state = ReviewState()
    state.mark_result_failed("result_001.md", 1, "source evidence contradicts report")
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="EXPORT followthrough gap",
        scores={"export_followthrough": 0.5},
        advisor_id="global_completeness",
        issues=[
            {
                "id": "cmp-export-gap",
                "category": "export_followthrough",
                "target": "EXPORT_L42",
                "required_action": "跟入 EXPORT_L42 到 sink",
                "actionable_by": "worker",
            }
        ],
    )
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="boundary bypass not checked",
        scores={"code_evidence_depth": 0.4},
        advisor_id="global_depth",
        issues=[
            {
                "id": "dpt-boundary",
                "category": "scan_depth",
                "target": "len check",
                "required_action": "检查 len=0/1/0xffff 绕过",
                "actionable_by": "worker",
            }
        ],
    )

    agent = FakeWorkerAgent()
    response = asyncio.run(
        WorkerExecutor(agent_registry=None, recorder=None)._execute_rework_sequence(  # type: ignore[arg-type]
            wf_def=wf,
            ctx=ctx,
            review_state=state,
            agent=agent,
            session_id="worker-session-1",
            system_prompt="system",
        )
    )

    assert response.metadata["rework_sequence"] is True
    assert response.metadata["skip_reflection_after_worker"] is True
    assert len(agent.messages) == 4
    assert {item["session_id"] for item in agent.messages} == {"worker-session-1"}
    assert agent.messages[0]["kind"] == "multi_turn"
    assert all(item["kind"] == "send_message" for item in agent.messages[1:])
    assert "全面性评审 -> 漏报补扫信号" in agent.messages[0]["message"]
    assert "误报压制与失败结果修复" in agent.messages[1]["message"]
    assert "依据评审缺口挖掘遗漏漏洞" in agent.messages[2]["message"]
    assert "Rework Handoff" in agent.messages[3]["message"]

    for step_key in (
        "worker::rework_triage",
        "worker::rework_fp_repair",
        "worker::rework_missed_hunt",
        "worker::rework_handoff",
    ):
        checkpoint = load_step_checkpoint(
            work_dir,
            cycle=2,
            phase="worker",
            step_key=step_key,
        )
        assert checkpoint is not None
        assert checkpoint["status"] == "completed"


def test_repeated_analysis_issue_adds_residual_protocol_to_closure_prompt(tmp_path: Path) -> None:
    task_file = tmp_path / "task.md"
    task_file.write_text("# scan task\n", encoding="utf-8")
    work_dir = tmp_path / "work"
    (work_dir / "results").mkdir(parents=True)
    wf = _workflow_with_worker_prompt(
        Path("prompts/vuln_scan/worker_user.md"),
        Path("prompts/vuln_scan/summary.md"),
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(task_file),
        working_dir=str(work_dir),
        cycle=3,
        review_mode="closure",
        failed_result_items=[],
        plateau_reason="同一全局评审 issue 连续出现 2 轮",
    )
    state = ReviewState()
    state.workflow_mode = "closure"
    issue = {
        "id": "CMP-ppldm-slot0",
        "category": "coverage_gap",
        "target": "PP/LDM slot-0",
        "severity": "high",
        "required_action": "查证 PP/LDM slot-0 control-info production chain",
        "actionable_by": "worker",
        "blocking_type": "analysis_gap",
        "acceptance_criteria": "补齐源码证据或记录 residual",
    }
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="slot-0 未闭环",
        scores={"export_followthrough": 0.6},
        issues=[issue],
    )
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="slot-0 仍未闭环",
        scores={"export_followthrough": 0.62},
        issues=[issue],
    )

    prompt = WorkerExecutor(agent_registry=None, recorder=None)._build_user_prompt(  # type: ignore[arg-type]
        wf,
        ctx,
        state,
    )

    assert "重复阻塞项 ledger" in prompt
    assert "accepted_residual" in prompt
    assert "residual_cycle_003.md" in prompt
