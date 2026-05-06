from __future__ import annotations

from pathlib import Path

import pytest

from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.template import TemplateRenderError, render_string


def _workflow_with_worker_prompt(worker_prompt: Path, summary_prompt: Path) -> AtomicWorkflowDef:
    return AtomicWorkflowDef.model_validate(
        {
            "id": "wf",
            "name": "wf",
            "working_dir_template": "wf_{task_id}",
            "roles": {
                "worker": {
                    "agent_id": "worker",
                    "prompts": {
                        "work": {
                            "system_prompt_file": "prompts/vuln_scan/worker_system.md",
                            "user_prompt_file": str(worker_prompt),
                        },
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
    assert "本轮只修复 `summary.md`" in prompt
    assert "不要新增、删除、重写或重新编号 `results/result_NNN.md`" in prompt


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
