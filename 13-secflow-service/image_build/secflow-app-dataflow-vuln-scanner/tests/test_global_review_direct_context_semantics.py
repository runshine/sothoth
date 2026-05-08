from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.state import GlobalReviewRecord, ReviewState


def _make_executor(tmp_path: Path) -> tuple[GlobalReviewExecutor, ExecutionRecorder]:
    recorder = ExecutionRecorder(str(tmp_path))
    executor = GlobalReviewExecutor(AgentRuntimeRegistry(), recorder)
    return executor, recorder


def _prepare_work_dir(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    work_dir = tmp_path / "atomic"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    summary_path = work_dir / "summary.md"
    summary_path.write_text(
        "# summary\n\n## 7. 局限性与未覆盖区域\n",
        encoding="utf-8",
    )
    task_path = work_dir / "task.md"
    task_path.write_text("# task\n", encoding="utf-8")
    return work_dir, summary_path, results_dir, task_path


def _global_advisor() -> AdvisorInstanceDef:
    return AdvisorInstanceDef(
        instance_id="global_quality",
        agent_id="advisor",
        role_name="全局评审",
        re_review_on_cycle=True,
        system_prompt_file="sys.md",
        user_prompt_template="user.md",
        score_fields=["input_coverage", "export_followthrough"],
        score_thresholds_start={"input_coverage": 0.8, "export_followthrough": 0.7},
        score_thresholds={"input_coverage": 1.0, "export_followthrough": 0.95},
        score_threshold_ramp_cycles=5,
    )


def test_direct_context_falls_back_to_workspace_previous_limitations_for_historical_runs(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    snapshots_dir = work_dir / "_meta" / "summary_snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    (snapshots_dir / "cycle_001_after_summary.md").write_text(
        "# summary cycle 1\n\n## 7. 局限性与未覆盖区域\n",
        encoding="utf-8",
    )
    (work_dir / "previous_limitations.md").write_text(
        "# 局限性与覆盖盲区记录\n\n- 未跟入 EXPORT: IPSEC_SOCK_SendToSocket\n",
        encoding="utf-8",
    )

    context = executor._build_review_context_text(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    assert context["previous_limitations_file"].endswith("previous_limitations.md")
    assert "上一轮局限性来源: workspace_fallback" in context["context_text"]
    assert "上一轮局限性快照缺失或仅为占位内容" in context["context_text"]
    assert "IPSEC_SOCK_SendToSocket" in context["context_text"]


def test_direct_context_prefers_snapshotted_previous_limitations_sidecar(
    tmp_path: Path,
) -> None:
    executor, recorder = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    original_content = (
        "# 局限性与覆盖盲区记录\n\n"
        "- 上一轮未完成: USED 终点逐项清单\n"
        "- 上一轮未完成: TOCTOU 静态分析\n"
    )
    (work_dir / "previous_limitations.md").write_text(original_content, encoding="utf-8")
    asyncio.run(recorder.snapshot_summary(str(work_dir), cycle=1))

    (work_dir / "previous_limitations.md").write_text(
        "# 当前轮新内容\n\n- 这是本轮更新后的 sidecar，不应被当作上一轮快照\n",
        encoding="utf-8",
    )

    context = executor._build_review_context_text(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    assert "上一轮局限性来源: sidecar_snapshot" in context["context_text"]
    assert context["previous_limitations_file"].endswith(
        "cycle_001_previous_limitations.md"
    )
    assert "USED 终点逐项清单" in context["context_text"]
    assert "本轮更新后的 sidecar" not in context["context_text"]


def test_direct_context_marks_review_feedback_as_pre_review_snapshot(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    review_state = ReviewState()
    review_state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="仍有 issue",
        scores={"report_completeness": 0.6},
        issues=[
            {
                "id": "report:state-sync",
                "category": "report_completeness",
                "target": "summary.md#7",
                "severity": "high",
                "required_action": "补全 issue 关闭说明",
            }
        ],
        resolved_issue_ids=[],
    )
    review_state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_quality",
            passed=False,
            feedback="仍有 issue",
            scores={"report_completeness": 0.6},
            issues=[
                {
                    "id": "report:state-sync",
                    "category": "report_completeness",
                    "target": "summary.md#7",
                    "severity": "high",
                    "required_action": "补全 issue 关闭说明",
                }
            ],
        )
    )

    context = executor._build_review_context_text(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=review_state,
    )

    assert "当前结果状态摘要（评审前快照）" in context["context_text"]
    assert "补全 issue 关闭说明" in context["context_text"]
    user_prompt = Path("prompts/vuln_scan/global_review_completeness_user.md").read_text(encoding="utf-8")
    sys_prompt = Path("prompts/vuln_scan/global_review_completeness_sys.md").read_text(encoding="utf-8")
    assert "本轮评审开始前" in user_prompt
    assert "评审反馈" in user_prompt
    assert "不要写任何文件" in user_prompt
    assert "Closure 模式" in sys_prompt


def test_direct_context_separates_supporting_docs_from_reviewable_results(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    (results_dir / "USED_ENDPOINTS.md").write_text("# appendix\n", encoding="utf-8")
    supporting_docs_dir = work_dir / "supporting_docs"
    supporting_docs_dir.mkdir(parents=True, exist_ok=True)
    (supporting_docs_dir / "REMOVED.md").write_text("# removed\n", encoding="utf-8")

    context = executor._build_review_context_text(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=1,
        review_state=ReviewState(),
    )

    assert "result_001.md" in context["context_text"]
    assert "USED_ENDPOINTS.md" not in context["context_text"]
    assert "REMOVED.md" in context["context_text"]
    assert context["supporting_docs_dir"].endswith("supporting_docs")


def test_global_score_thresholds_fail_close_when_passed_json_scores_are_too_low(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    advisor = _global_advisor()

    parsed = type("Parsed", (), {
        "passed": True,
        "feedback": "PASS（通过） - reviewer 声称通过",
        "feedback_detail": "reviewer 声称通过",
        "verdict": "PASS",
        "scores": {
            "input_coverage": 0.90,
            "export_followthrough": 1.0,
        },
    })()

    passed, feedback, detail, verdict, issues = executor._apply_score_thresholds(
        parsed,
        advisor,
        cycle=5,
    )

    assert passed is False
    assert verdict == "FAIL"
    assert "框架分数阈值校验未通过" in detail
    assert "input_coverage=0.90" in detail
    assert issues == [
            {
                "id": "score-threshold:input-coverage",
                "category": "score_threshold",
                "target": "input_coverage",
                "severity": "high",
                "required_action": "补齐 input_coverage 对应的分析证据，或将该分数提升到至少 1.00 后再通过全局评审",
                "detail": "input_coverage=0.90 低于本轮通过阈值 1.00（Cycle 5）",
                "owner": "worker",
                "actionable_by": "worker",
                "blocking_type": "evidence_gap",
                "acceptance_criteria": "input_coverage 分数达到本轮阈值 1.00，或 summary 中诚实说明不可闭环 residual。",
            }
        ]
    assert feedback.startswith("FAIL（未通过）")


def test_global_score_thresholds_do_not_override_closure_pass_after_residual(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    advisor = _global_advisor()

    parsed = type("Parsed", (), {
        "passed": True,
        "feedback": "closure residual accepted",
        "feedback_detail": "accepted_residual 已记录且自洽",
        "verdict": "PASS",
        "scores": {
            "input_coverage": 0.90,
            "export_followthrough": 0.90,
        },
    })()

    passed, feedback, detail, verdict, issues = executor._apply_score_thresholds(
        parsed,
        advisor,
        cycle=5,
        workflow_mode="closure",
    )

    assert passed is True
    assert verdict == "PASS"
    assert feedback == "closure residual accepted"
    assert "accepted_residual" in detail
    assert issues == []


def test_profile_gate_fast_bypasses_missing_ledger_while_balanced_fails(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="fast",
    ) == []

    issues = executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    )

    assert [item["id"] for item in issues] == [
        "PROFILE-balanced-coverage-ledger-missing"
    ]
    assert issues[0]["actionable_by"] == "framework"


def test_profile_gate_balanced_blocks_under_extracted_and_open_high_obligations(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    meta_dir = tmp_path / "_meta"
    meta_dir.mkdir()
    (meta_dir / "coverage_ledger.json").write_text(
        json.dumps({
            "coverage_obligations": {
                "quality": {
                    "declared_counts": {
                        "input": 5,
                        "export": 10,
                        "used": 10,
                        "cleaned": 0,
                        "star": 1,
                    },
                },
                "entries": [
                    {
                        "id": "EXPORT:memcpy",
                        "kind": "export",
                        "risk": "high",
                        "documented": False,
                        "status": "open",
                        "evidence_sources": [],
                    },
                    {
                        "id": "INPUT:1",
                        "kind": "input",
                        "risk": "medium",
                        "documented": False,
                        "status": "open",
                        "evidence_sources": [],
                    },
                ],
            },
        }),
        encoding="utf-8",
    )

    issues = executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    )
    issue_ids = {item["id"] for item in issues}

    assert "PROFILE-balanced-coverage-under-extracted" in issue_ids
    assert "PROFILE-balanced-coverage-open-required" in issue_ids
    assert {item["actionable_by"] for item in issues} == {"framework", "worker"}


def test_profile_gate_strict_rejects_summary_only_required_evidence(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    meta_dir = tmp_path / "_meta"
    meta_dir.mkdir()
    (meta_dir / "coverage_ledger.json").write_text(
        json.dumps({
            "coverage_obligations": {
                "quality": {
                    "declared_counts": {
                        "input": 0,
                        "export": 0,
                        "used": 0,
                        "cleaned": 0,
                        "star": 0,
                    },
                },
                "entries": [
                    {
                        "id": "USED:RAW_U32@L130",
                        "kind": "used",
                        "risk": "high",
                        "documented": True,
                        "status": "documented",
                        "evidence_sources": ["summary.md"],
                    },
                ],
            },
        }),
        encoding="utf-8",
    )

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    ) == []

    issues = executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="strict",
    )

    assert [item["id"] for item in issues] == [
        "PROFILE-audit-summary-only-evidence"
    ]
    assert issues[0]["actionable_by"] == "worker"


def test_direct_context_extracts_previous_limitations_section_with_nested_subheadings(
    tmp_path: Path,
) -> None:
    executor, recorder = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    summary_path.write_text(
        "# summary\n\n## 7. 局限性与未覆盖区域\n\n### 7.1 未解决\n- 未跟入 EXPORT A\n\n### 7.2 后续方向\n- 需要补 USED B\n",
        encoding="utf-8",
    )
    asyncio.run(recorder.snapshot_summary(str(work_dir), cycle=1))

    context = executor._build_review_context_text(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    assert "上一轮局限性来源: sidecar_snapshot" in context["context_text"]
    assert "### 7.1 未解决" in context["context_text"]
    assert "未跟入 EXPORT A" in context["context_text"]
