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
        score_fields=["coverage"],
        score_thresholds_start={"coverage": 0.8},
        score_thresholds={"coverage": 1.0},
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
    assert "覆盖是否足够全面" in user_prompt
    assert "全面性评审员" in user_prompt
    assert "scores` 只包含 `coverage`" in user_prompt
    assert "只保留 3 个字段" in user_prompt
    assert "`id`、`target`、`required_action`" in user_prompt
    assert "禁止写入或修改任何文件" in user_prompt


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


def test_global_score_threshold_helpers_removed_from_executor(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)

    assert not hasattr(executor, "_apply_score_thresholds")
    assert not hasattr(executor, "_score_threshold_issues")
    assert not hasattr(executor, "_format_score_threshold_feedback")


def test_load_existing_global_review_record_recovers_original_pass_from_legacy_threshold_fail(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)
    _ = summary_path, results_dir, task_path

    record_dir = work_dir / "reviews" / "global" / "cycle_001"
    record_dir.mkdir(parents=True, exist_ok=True)
    (record_dir / "global_quality.json").write_text(
        json.dumps(
            {
                "advisor_instance_id": "global_quality",
                "cycle": 1,
                "passed": False,
                "verdict": "FAIL",
                "scores": {"coverage": 0.84},
                "feedback": "FAIL（未通过） - coverage=0.84 低于本轮通过阈值 0.90（Cycle 1）",
                "feedback_detail": "reviewer 原本判定通过。\n\n[框架分数阈值校验未通过]\n- coverage=0.84 低于本轮通过阈值 0.90（Cycle 1）",
                "raw_response": json.dumps(
                    {
                        "passed": True,
                        "verdict": "PASS",
                        "feedback": "reviewer 原本判定通过",
                        "scores": {"coverage": 0.84},
                        "confidence": 0.9,
                        "issues": [],
                        "resolved_issues": [],
                    },
                    ensure_ascii=False,
                ),
                "issues": [
                    {
                        "id": "global_quality:score-threshold:coverage",
                        "category": "score_threshold",
                        "target": "coverage",
                    }
                ],
                "parser_mode": "canonical_json",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    record = executor._load_existing_global_review_record(
        work_dir=str(work_dir),
        cycle=1,
        advisor_def=_global_advisor(),
    )

    assert record is not None
    assert record["passed"] is True
    assert "reviewer 原本判定通过" in record["feedback"]
    assert record["issues"] == []
    assert record["scores"] == {"coverage": 0.84}


def test_profile_gate_no_longer_emits_artifact_issues(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="fast",
    ) == []
    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    ) == []


def test_profile_gate_ignores_removed_structured_artifact_files(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    meta_dir = tmp_path / "_meta"
    meta_dir.mkdir()
    (meta_dir / "legacy_profile_gate.json").write_text(
        json.dumps({"entries": [{"id": "EXPORT:memcpy", "status": "open"}]}),
        encoding="utf-8",
    )

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    ) == []


def test_profile_gate_strict_has_no_summary_only_artifact_rule(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    meta_dir = tmp_path / "_meta"
    meta_dir.mkdir()
    (meta_dir / "legacy_profile_gate.json").write_text(
        json.dumps({"entries": [{"id": "USED:RAW_U32@L130", "evidence_sources": ["summary.md"]}]}),
        encoding="utf-8",
    )

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="balanced",
    ) == []

    assert executor._profile_gate_issues(
        work_dir=str(tmp_path),
        review_profile="strict",
    ) == []


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


def test_global_review_execute_no_longer_calls_dead_profile_gate_hook(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    task_file = tmp_path / "task.md"
    summary_file = tmp_path / "summary.md"
    results_dir = tmp_path / "results"
    task_file.write_text("# task\n", encoding="utf-8")
    summary_file.write_text("# summary\n", encoding="utf-8")
    results_dir.mkdir()
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    async def _fake_run_single_advisor(**_: object) -> dict[str, object]:
        return {
            "advisor_id": "global_quality",
            "role_name": "全局评审",
            "passed": True,
            "feedback": "PASS（通过）",
            "detail_feedback": "PASS（通过）",
            "scores": {"coverage": 1.0},
            "issues": [],
            "already_recorded": False,
        }

    called = {"profile_gate": False}

    def _should_not_run(**_: object) -> list[dict[str, str]]:
        called["profile_gate"] = True
        raise AssertionError("dead profile gate hook should not be called")

    executor._run_single_advisor = _fake_run_single_advisor  # type: ignore[method-assign]
    executor._profile_gate_issues = _should_not_run  # type: ignore[method-assign]

    passed, feedback = asyncio.run(
        executor.execute(
            advisors_cfg=[_global_advisor()],
            task_file=str(task_file),
            summary_file=str(summary_file),
            results_dir=str(results_dir),
            work_dir=str(tmp_path),
            cycle=1,
            review_state=ReviewState(),
            advisor_sessions={},
        )
    )

    assert passed is True
    assert feedback == ""
    assert called["profile_gate"] is False
