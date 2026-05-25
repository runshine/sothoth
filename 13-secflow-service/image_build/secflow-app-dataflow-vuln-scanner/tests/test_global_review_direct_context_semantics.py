from __future__ import annotations

import json
import re
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor


def _make_executor(tmp_path: Path) -> tuple[GlobalReviewExecutor, ExecutionRecorder]:
    recorder = ExecutionRecorder(str(tmp_path))
    executor = GlobalReviewExecutor(AgentRuntimeRegistry(), recorder)
    return executor, recorder


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


def test_global_review_user_prompts_no_longer_depend_on_framework_snapshot_context() -> None:
    expected_vars = {
        "advisor_instance_id",
        "advisor_role_name",
        "results_dir",
        "summary_file",
        "supporting_docs_dir",
        "task_file",
    }
    for name in (
        "global_review_completeness_user.md",
        "global_review_depth_user.md",
    ):
        text = Path(f"prompts/vuln_scan/{name}").read_text(encoding="utf-8")
        placeholders = set(re.findall(r"\{([a-zA-Z0-9_]+)\}", text))
        assert placeholders == expected_vars
        assert "{review_context}" not in text
        assert "{previous_limitations_file}" not in text
        assert "{results_manifest_file}" not in text
        assert "{result_relations_manifest_file}" not in text


def test_global_review_schema_repair_hint_is_compact(tmp_path: Path) -> None:
    executor, _ = _make_executor(tmp_path)

    hint = executor._build_schema_repair_hint(
        task_file="/tmp/task.md",
        summary_file="/tmp/summary.md",
        results_dir="/tmp/results",
        supporting_docs_dir="/tmp/supporting_docs",
    )

    assert "task=`/tmp/task.md`" in hint
    assert "summary=`/tmp/summary.md`" in hint
    assert "results_dir=`/tmp/results`" in hint
    assert "supporting_docs_dir=`/tmp/supporting_docs`" in hint
    assert "previous_limitations" not in hint


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
            "coverage": 0.90,
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
    assert "coverage=0.90" in detail
    assert issues == [
        {
            "id": "score-threshold:coverage",
            "category": "score_threshold",
            "target": "coverage",
            "severity": "high",
            "required_action": "补齐 coverage 对应的分析证据，或将该分数提升到至少 1.00 后再通过全局评审",
            "detail": "coverage=0.90 低于本轮通过阈值 1.00（Cycle 5）",
            "owner": "worker",
            "actionable_by": "worker",
            "blocking_type": "evidence_gap",
            "acceptance_criteria": "coverage 分数达到本轮阈值 1.00，或 summary 中诚实说明不可闭环 residual。",
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
            "coverage": 0.90,
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
