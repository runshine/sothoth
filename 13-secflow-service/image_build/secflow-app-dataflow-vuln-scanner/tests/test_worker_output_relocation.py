from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.state import FailedResultItem, ReviewState


def test_relocate_misplaced_outputs_moves_summary_and_results(tmp_path: Path):
    work_dir = tmp_path / "work"
    call_dir = work_dir / "sessions" / "pi_testsession" / "calls" / "003_deadbeef"
    misplaced_results = call_dir / "results"
    misplaced_results.mkdir(parents=True, exist_ok=True)

    (call_dir / "summary.md").write_text("# moved summary\n", encoding="utf-8")
    (misplaced_results / "result_001.md").write_text("# moved result\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        worker_session_id="pi_testsession",
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._relocate_misplaced_outputs(ctx, turn_count=3)

    assert (work_dir / "summary.md").read_text(encoding="utf-8") == "# moved summary\n"
    assert (work_dir / "results" / "result_001.md").read_text(encoding="utf-8") == "# moved result\n"
    assert not (call_dir / "summary.md").exists()
    assert not (misplaced_results / "result_001.md").exists()
    assert not misplaced_results.exists()


def test_reconcile_results_after_rework_restores_protected_file_and_preserves_new_content(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    (results_dir / "result_001.md").write_text("# passed\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# failed\n", encoding="utf-8")

    summary_path = work_dir / "summary.md"
    summary_path.write_text("see result_001.md\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        pre_cycle_result_files=["result_001.md", "result_002.md"],
        protected_result_files=["result_001.md"],
        protected_result_snapshots={"result_001.md": "# passed\n"},
        historical_max_result_number=2,
        next_result_number=3,
    )

    (results_dir / "result_001.md").write_text("# overwritten by new finding\n", encoding="utf-8")

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._reconcile_results_after_rework(ctx)

    assert (results_dir / "result_001.md").read_text(encoding="utf-8") == "# passed\n"
    assert (results_dir / "result_003.md").read_text(encoding="utf-8") == "# overwritten by new finding\n"
    assert summary_path.read_text(encoding="utf-8") == "see result_003.md\n"



def test_reconcile_results_after_rework_renames_new_low_number_report_and_updates_summary(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    (results_dir / "result_001.md").write_text("# existing\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# brand new\n", encoding="utf-8")
    summary_path = work_dir / "summary.md"
    summary_path.write_text("see result_002.md\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        pre_cycle_result_files=["result_001.md"],
        protected_result_files=[],
        protected_result_snapshots={},
        historical_max_result_number=4,
        next_result_number=5,
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._reconcile_results_after_rework(ctx)

    assert not (results_dir / "result_002.md").exists()
    assert (results_dir / "result_005.md").read_text(encoding="utf-8") == "# brand new\n"
    assert summary_path.read_text(encoding="utf-8") == "see result_005.md\n"



def test_reconcile_results_after_rework_backs_up_removed_failed_results(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    (results_dir / "result_002.md").write_text("# survivor\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        summary_file=str(work_dir / "summary.md"),
        results_dir=str(results_dir),
        pre_cycle_result_files=["result_001.md", "result_002.md"],
        protected_result_files=[],
        protected_result_snapshots={},
        historical_max_result_number=2,
        next_result_number=3,
        failed_result_snapshots={"result_001.md": "# removed failed report\n"},
        failed_result_reasons={"result_001.md": "误报，已从最终结果删除"},
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._reconcile_results_after_rework(ctx)

    backup_dir = work_dir / "removed_results" / "cycle_002"
    assert (backup_dir / "result_001.md").read_text(encoding="utf-8") == "# removed failed report\n"
    meta_text = (backup_dir / "result_001.json").read_text(encoding="utf-8")
    assert '"original_filename": "result_001.md"' in meta_text
    assert '"reason": "误报，已从最终结果删除"' in meta_text


def test_reconcile_results_after_rework_keeps_explicitly_withdrawn_failed_results(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    withdrawn_text = (
        "# ~~VULN-007~~ [已撤回]\n\n"
        "- **状态**: ❌ 已撤回 — 经评审确认为误报\n"
    )
    (results_dir / "result_001.md").write_text("# survivor\n", encoding="utf-8")
    (results_dir / "result_007.md").write_text(withdrawn_text, encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        summary_file=str(work_dir / "summary.md"),
        results_dir=str(results_dir),
        pre_cycle_result_files=["result_001.md", "result_007.md"],
        protected_result_files=[],
        protected_result_snapshots={},
        historical_max_result_number=7,
        next_result_number=8,
        failed_result_snapshots={"result_007.md": "# old failed report\n"},
        failed_result_reasons={"result_007.md": "底层问题不存在，报告应撤回"},
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._reconcile_results_after_rework(ctx)

    assert (results_dir / "result_007.md").read_text(encoding="utf-8") == withdrawn_text
    assert not (work_dir / "removed_results" / "cycle_002").exists()


def test_reconcile_results_after_rework_keeps_chinese_retraction_variants(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    retraction = (
        "# 修正：撤回 VULN-008\n\n"
        "- **本报告性质**: 撤回说明\n"
        "- **状态**: 确认为误报，非漏洞\n"
    )
    (results_dir / "result_008.md").write_text(retraction, encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=3,
        summary_file=str(work_dir / "summary.md"),
        results_dir=str(results_dir),
        pre_cycle_result_files=["result_008.md"],
        failed_result_snapshots={"result_008.md": "# old\n"},
        failed_result_reasons={"result_008.md": "证伪，撤回"},
        historical_max_result_number=8,
        next_result_number=9,
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._reconcile_results_after_rework(ctx)

    assert (results_dir / "result_008.md").read_text(encoding="utf-8") == retraction
    assert not (work_dir / "removed_results" / "cycle_003").exists()


def test_relocate_misplaced_outputs_moves_supporting_docs_to_supporting_docs_dir(tmp_path: Path):
    work_dir = tmp_path / "work"
    call_dir = work_dir / "sessions" / "pi_testsession" / "calls" / "003_deadbeef"
    misplaced_results = call_dir / "results"
    misplaced_results.mkdir(parents=True, exist_ok=True)

    (misplaced_results / "USED_ENDPOINTS.md").write_text("# appendix\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        worker_session_id="pi_testsession",
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._relocate_misplaced_outputs(ctx, turn_count=3)

    assert (work_dir / "supporting_docs" / "USED_ENDPOINTS.md").read_text(encoding="utf-8") == "# appendix\n"


def test_review_delta_text_contains_review_feedback(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# passed\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# failed\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        worker_session_id="worker_wf_task",
    )
    state = ReviewState()
    state.mark_result_passed("result_001.md", 1)
    state.mark_result_failed("result_002.md", 1, "needs fix")

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    delta = executor._build_review_delta_text(
        ctx=ctx,
        review_state=state,
        current_result_files=["result_001.md", "result_002.md"],
    )

    assert "第 2 轮评审反馈摘要" in delta
    assert "已通过评审：1" in delta
    assert "未通过评审：1" in delta
    assert "result_001.md" in delta
    assert "result_002.md" in delta
    assert "needs fix" in delta


class _SummaryCaptureAgent:
    def __init__(self) -> None:
        self.last_message = ""

    async def send_message(self, message: str, session_id: str | None = None, working_dir: str | None = None):
        self.last_message = message
        work_dir = Path(working_dir or ".")
        results_dir = work_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        (work_dir / "summary.md").write_text(
            "# summary\n\n"
            "## 5. 漏洞汇总表\n\n"
            "| 编号 | 文件 | 漏洞 |\n"
            "|---|---|---|\n"
            "| 001 | result_001.md | demo |\n\n"
            "## 7. 局限性与未覆盖区域\n\n- gap\n",
            encoding="utf-8",
        )
        (results_dir / "result_001.md").write_text("# result 001\n\n## VULN-001\n", encoding="utf-8")
        return AgentResponse(content="ok", conversation_id=session_id, turn_count=1, finished=True)


class _SummaryCaptureRegistry:
    def __init__(self, agent: _SummaryCaptureAgent) -> None:
        self._agent = agent

    def get(self, agent_id: str) -> _SummaryCaptureAgent:
        return self._agent


def test_execute_summary_uses_real_review_state_in_summary_context(tmp_path: Path):
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# passed\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# failed\n", encoding="utf-8")

    prompt_file = tmp_path / "summary_prompt.md"
    prompt_file.write_text("PROMPT\n\n{summary_runtime_context}\n", encoding="utf-8")

    agent = _SummaryCaptureAgent()
    executor = WorkerExecutor(
        agent_registry=_SummaryCaptureRegistry(agent),  # type: ignore[arg-type]
        recorder=None,  # type: ignore[arg-type]
    )
    wf_def = SimpleNamespace(
        roles=SimpleNamespace(
            worker=SimpleNamespace(
                agent_id="pi-worker",
                prompts=SimpleNamespace(
                    summary=SimpleNamespace(
                        prompt_file=str(prompt_file),
                        output_summary_filename="summary.md",
                        output_results_dir="results",
                    )
                ),
            )
        )
    )
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=2,
        worker_session_id="worker_cycle_002",
        review_mode="discovery",
    )
    state = ReviewState()
    state.mark_result_passed("result_001.md", 1)
    state.mark_result_failed("result_002.md", 1, "needs fix")
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="need used coverage",
        scores={"used_coverage": 0.8},
        issues=[
            {
                "id": "GBL-USED",
                "category": "used_coverage",
                "severity": "medium",
                "required_action": "补充 USED 对账",
                "actionable_by": "worker",
            }
        ],
        resolved_issue_ids=[],
    )

    asyncio.run(executor.execute_summary(wf_def, ctx, state))

    # 单 session 模式下，summary 不再注入完整 memory digest，只注入简洁上下文
    assert "当前轮次：第 2 轮" in agent.last_message
    assert "discovery" in agent.last_message


def test_rework_prompt_filters_framework_issues_and_stale_deleted_results(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "summary.md").write_text("## 7. 局限性与未覆盖区域\n\n- old gap\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=3,
        pre_cycle_result_files=["result_001.md"],
        next_result_number=7,
        review_mode="discovery",
        failed_result_items=[],
    )

    state = ReviewState()
    state.mark_result_failed("result_001.md", 1, "still needs work")
    state.mark_result_failed("result_999.md", 1, "stale deleted result")
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="need fixes",
        scores={"report_completeness": 0.6},
        issues=[
            {
                "id": "worker-gap",
                "category": "used_coverage",
                "target": "USED table",
                "severity": "medium",
                "required_action": "补充 USED 覆盖矩阵",
                "actionable_by": "worker",
            },
            {
                "id": "framework-sync",
                "category": "report_completeness",
                "target": "issues.json",
                "severity": "high",
                "required_action": "同步 issues.json 与 resolved_issues",
                "actionable_by": "framework",
            },
        ],
        resolved_issue_ids=[],
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    prompt = executor._build_rework_prompt(ctx, state)

    assert "worker-gap" in prompt  # active worker backlog is now injected for closure
    assert "framework-sync" not in prompt
    assert "result_001.md" in prompt
    assert "result_999.md" not in prompt
    assert "supporting_docs" in prompt
    assert "后续显式 summary 阶段" in prompt
    assert "近期全局评审反馈" in prompt or "未通过评审" in prompt
    assert "修复/删除未通过结果" in prompt
    assert "不要继续扩张攻击面" in prompt
    assert "新增" in prompt and "result_NNN.md" in prompt


def test_initial_worker_context_marks_summary_outputs_as_deferred(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=1,
        review_mode="discovery",
    )
    state = ReviewState()

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    context = executor._build_initial_worker_context(
        ctx=ctx,
        review_state=state,
        current_result_files=[],
    )

    assert "本阶段正式结果目录" in context
    assert "本阶段辅助文档目录" in context
    assert "后续 summary 阶段整理的总结报告" in context
    assert "后续 summary 阶段同步的局限性记录" in context
    assert "本阶段输出位置 contract" in context
    assert "将在后续显式 summary 阶段统一整理" in context


def test_reflection_scope_becomes_mode_aware_in_rework_cycles(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=4,
        review_mode="closure",
        failed_result_items=[],
    )
    state = ReviewState()
    state.record_global_review_result(
        cycle=3,
        passed=False,
        feedback="need rework",
        scores={"report_completeness": 0.5},
        issues=[
            {
                "id": "worker-gap",
                "category": "used_coverage",
                "target": "USED table",
                "severity": "medium",
                "required_action": "补充 USED 覆盖矩阵",
            }
        ],
        resolved_issue_ids=[],
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    scope = executor._build_reflection_scope(ctx, state)

    assert "返工/收敛阶段" in scope
    assert "不要重新把任务扩张成全量攻击面重扫" in scope
    # issue IDs no longer injected; feedback chain used instead
    assert "supporting_docs" in scope


def test_rework_prompt_switches_to_result_repair_only_without_worker_issues(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "summary.md").write_text("## 7. 局限性与未覆盖区域\n\n- old gap\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=3,
        pre_cycle_result_files=["result_009.md"],
        next_result_number=10,
        review_mode="discovery",
        failed_result_items=[FailedResultItem(filename="result_009.md", reason="needs fix")],
    )

    state = ReviewState()
    state.mark_result_failed("result_009.md", 2, "needs fix")

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    prompt = executor._build_rework_prompt(ctx, state)

    # 无 worker issue 时，不应出现 issue 章节，但应出现结果修复要求
    assert "未关闭的 Worker 可执行 issue" not in prompt
    assert "修复/删除未通过结果" in prompt
    assert "只聚焦**修复/删除未通过结果**" in prompt
    assert "不要继续扩张攻击面" in prompt
    assert "## 本轮双目标（必须同时满足）" not in prompt


def test_rework_prompt_marks_issues_on_protected_results_as_no_direct_edit(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "summary.md").write_text("## 7. 局限性与未覆盖区域\n\n- old gap\n", encoding="utf-8")

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        cycle=3,
        pre_cycle_result_files=["result_005.md"],
        protected_result_files=["result_005.md"],
        next_result_number=11,
        review_mode="discovery",
        failed_result_items=[FailedResultItem(filename="result_009.md", reason="needs fix")],
    )

    state = ReviewState()
    state.mark_result_failed("result_009.md", 2, "needs fix")
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="need support",
        scores={"code_evidence_depth": 0.6},
        issues=[
            {
                "id": "result-005-confidence-weak",
                "category": "code_evidence_depth",
                "target": "result_005.md",
                "severity": "medium",
                "required_action": "补充 result_005 证据",
                "actionable_by": "worker",
            }
        ],
        resolved_issue_ids=[],
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    prompt = executor._build_rework_prompt(ctx, state)

    # Issue-on-protected-results removed; feedback chain handles this
    assert "未通过评审" in prompt or "评审反馈" in prompt or "近期" in prompt


def test_summary_syncs_previous_limitations_sidecar_from_section(tmp_path: Path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    summary_path = work_dir / "summary.md"
    summary_path.write_text(
        "# summary\n\n## 7. 局限性与未覆盖区域\n\n### 7.1 未解决\n- gap A\n",
        encoding="utf-8",
    )

    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file=str(tmp_path / "task.md"),
        working_dir=str(work_dir),
        summary_file=str(summary_path),
    )

    executor = WorkerExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    executor._sync_previous_limitations_sidecar(ctx)

    sidecar = work_dir / "previous_limitations.md"
    assert sidecar.exists()
    text = sidecar.read_text(encoding="utf-8")
    assert "### 7.1 未解决" in text
    assert "gap A" in text


def test_record_reflection_keeps_cycle_scoped_history(tmp_path: Path):
    recorder = ExecutionRecorder(str(tmp_path))
    work_dir = tmp_path / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    asyncio.run(recorder.record_reflection(str(work_dir), 1, "reflect_completeness", "cycle1", cycle=1))
    asyncio.run(recorder.record_reflection(str(work_dir), 1, "reflect_completeness", "cycle2", cycle=2))

    assert (work_dir / "_meta" / "reflections" / "cycle_001_reflect_001_reflect_completeness.json").exists()
    assert (work_dir / "_meta" / "reflections" / "cycle_002_reflect_001_reflect_completeness.json").exists()
