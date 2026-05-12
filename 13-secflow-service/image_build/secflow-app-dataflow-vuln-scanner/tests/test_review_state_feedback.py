from __future__ import annotations

import json

from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.models import parse_review_response
from app.pi_vuln_core.review.state import GlobalReviewRecord, ReviewState


def test_recent_issues_and_feedback_include_all_failed_advisors_in_cycle() -> None:
    state = ReviewState()
    state.global_review_history.extend(
        [
            GlobalReviewRecord(
                cycle=1,
                advisor_id="global_completeness",
                passed=False,
                feedback="coverage gap",
                scores={"used_coverage": 0.5},
                issues=[{"id": "CMP-1", "actionable_by": "worker"}],
            ),
            GlobalReviewRecord(
                cycle=1,
                advisor_id="global_depth",
                passed=False,
                feedback="depth gap",
                scores={"code_evidence_depth": 0.4},
                issues=[{"id": "DPT-1", "actionable_by": "worker"}],
            ),
        ]
    )

    issues = state.get_recent_issues(last_n=1)
    assert {item["id"] for item in issues} == {"CMP-1", "DPT-1"}
    assert {item["advisor_id"] for item in issues} == {
        "global_completeness",
        "global_depth",
    }

    feedback = state.format_recent_feedback(last_n=1)
    assert "global_completeness" in feedback
    assert "global_depth" in feedback
    assert "coverage gap" in feedback
    assert "depth gap" in feedback


def test_actionable_by_filter_ignores_framework_only_global_issues() -> None:
    state = ReviewState()
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="framework sync failed",
        scores={"report_completeness": 0.5},
        issues=[
            {
                "id": "schema-contract",
                "category": "schema_contract",
                "actionable_by": "framework",
            }
        ],
    )

    assert state.has_failures(actionable_by="worker") is False
    assert state.has_failures(actionable_by="framework") is True

    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=2,
            advisor_id="global_depth",
            passed=False,
            feedback="worker depth gap",
            issues=[
                {
                    "id": "DPT-2",
                    "category": "scan_depth",
                    "actionable_by": "worker",
                }
            ],
        )
    )
    assert state.has_failures(actionable_by="worker") is True


def test_framework_global_issues_are_not_classified_as_summary_repair() -> None:
    state = ReviewState()
    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="advisor contract failed",
            issues=[
                {
                    "id": "schema-contract",
                    "category": "schema_contract",
                    "actionable_by": "framework",
                }
            ],
        )
    )

    assert AtomicWorkflowEngine._classify_global_failure_scope(state) == "framework"


def test_mixed_framework_and_worker_global_issues_are_routed_to_rework() -> None:
    state = ReviewState()
    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="coverage still open and ledger extractor has one artifact",
            issues=[
                {
                    "id": "coverage-open-required",
                    "category": "coverage_gate",
                    "actionable_by": "worker",
                },
                {
                    "id": "ledger-artifact",
                    "category": "framework_gap",
                    "actionable_by": "framework",
                },
            ],
        )
    )

    assert AtomicWorkflowEngine._classify_global_failure_scope(state) == "analysis"


def test_parsed_global_issues_preserve_action_owner_fields() -> None:
    parsed = parse_review_response(
        json.dumps(
            {
                "passed": False,
                "feedback": "framework-owned metadata mismatch",
                "scores": {"report_completeness": 0.5},
                "confidence": 0.9,
                "issues": [
                    {
                        "id": "manifest-sync",
                        "category": "metadata_sync",
                        "target": "_meta/results_manifest.json",
                        "required_action": "重新同步框架生成清单",
                        "owner": "framework",
                        "actionable_by": "framework",
                    }
                ],
            },
            ensure_ascii=False,
        )
    )

    assert parsed.issues[0]["owner"] == "framework"
    assert parsed.issues[0]["actionable_by"] == "framework"


def test_parsed_global_issues_preserve_blocker_protocol_fields() -> None:
    parsed = parse_review_response(
        json.dumps(
            {
                "passed": False,
                "feedback": "external source required",
                "scores": {"report_completeness": 0.5},
                "confidence": 0.9,
                "issues": [
                    {
                        "id": "CMP-ppldm-slot0",
                        "category": "coverage_gap",
                        "target": "PP/LDM slot-0",
                        "required_action": "查证 slot-0 生产链",
                        "actionable_by": "worker",
                        "blocking_type": "needs_external_source",
                        "acceptance_criteria": "补齐生产链源码或记录 residual",
                        "max_retries_for_same_issue": 2,
                    }
                ],
            },
            ensure_ascii=False,
        )
    )

    issue = parsed.issues[0]
    assert issue["blocking_type"] == "needs_external_source"
    assert issue["acceptance_criteria"] == "补齐生产链源码或记录 residual"
    assert issue["max_retries_for_same_issue"] == 2


def test_issue_ledger_fingerprints_repeated_semantic_issues() -> None:
    state = ReviewState()
    issue = {
        "id": "CMP-ppldm-slot0",
        "category": "coverage_gap",
        "target": "PP/LDM slot-0",
        "required_action": "查证 PP/LDM slot-0 control-info production chain",
        "actionable_by": "worker",
    }

    first = state.update_issue_ledger(cycle=1, issues=[issue])
    second = state.update_issue_ledger(cycle=2, issues=[{**issue, "id": "CMP-ppldm-slot0-v2"}])

    assert first["max_consecutive_count"] == 1
    assert second["max_consecutive_count"] == 2
    assert second["repeated_signatures"]
    snapshot = state.get_issue_ledger_snapshot()
    assert snapshot["entries"][0]["seen_count"] == 2


def test_current_issue_records_follow_active_ledger_not_stale_history() -> None:
    state = ReviewState()
    stale_issue = {
        "id": "CMP-old",
        "category": "coverage_gap",
        "target": "result_001.md",
        "required_action": "旧 advisor 问题",
        "actionable_by": "worker",
    }
    active_profile_issue = {
        "id": "PROFILE-balanced-coverage-open-required",
        "category": "coverage_gate",
        "target": "_meta/coverage_ledger.json",
        "required_action": "关闭当前 open obligations",
        "actionable_by": "worker",
        "blocking_type": "coverage_obligation_open",
    }

    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="old failure",
            issues=[stale_issue],
        )
    )
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="old failure",
        issues=[stale_issue],
    )
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="profile gate failed",
        issues=[active_profile_issue],
    )

    current = state.get_current_issue_records()
    assert [item["id"] for item in current] == ["PROFILE-balanced-coverage-open-required"]
    assert current[0]["seen_count"] == 1
    assert current[0]["blocking_type"] == "coverage_obligation_open"


def test_review_feedback_snapshot_uses_active_issues_and_clears_after_pass(tmp_path) -> None:
    state = ReviewState()
    executor = GlobalReviewExecutor({}, object())
    stale_issue = {
        "id": "CMP-old",
        "category": "coverage_gap",
        "target": "result_001.md",
        "required_action": "旧 advisor 问题",
        "actionable_by": "worker",
    }
    active_profile_issue = {
        "id": "PROFILE-balanced-summary-only-evidence",
        "category": "coverage_gate",
        "target": "_meta/coverage_ledger.json",
        "required_action": "补充 supporting_docs 证据",
        "actionable_by": "worker",
        "blocking_type": "summary_only_evidence",
    }

    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="old failure",
            issues=[stale_issue],
        )
    )
    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="old failure",
        issues=[stale_issue],
    )
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="profile gate failed",
        issues=[active_profile_issue],
    )

    executor._write_review_feedback_snapshot(str(tmp_path), 2, state)
    snapshot = json.loads((tmp_path / "_meta" / "review_feedback" / "cycle_002.json").read_text(encoding="utf-8"))
    assert snapshot["issue_count"] == 1
    assert [item["id"] for item in snapshot["issues"]] == ["PROFILE-balanced-summary-only-evidence"]
    assert snapshot["issue_ledger_status"]["active_issue_count"] == 1

    state.record_global_review_result(
        cycle=3,
        passed=True,
        feedback="全局评审通过",
        issues=[],
    )
    executor._write_review_feedback_snapshot(str(tmp_path), 3, state)
    cleared = json.loads((tmp_path / "_meta" / "review_feedback" / "cycle_003.json").read_text(encoding="utf-8"))
    assert cleared["issue_count"] == 0
    assert cleared["issues"] == []


def test_worker_actionable_issue_takes_precedence_over_summary_category() -> None:
    state = ReviewState()
    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="EXPORT chain still shallow",
            issues=[
                {
                    "id": "export-followthrough",
                    "category": "report_completeness",
                    "target": "IPSEC_SOCK_SendToSocket",
                    "required_action": "继续下钻 EXPORT 链",
                    "actionable_by": "worker",
                }
            ],
        )
    )

    assert AtomicWorkflowEngine._classify_global_failure_scope(state) == "analysis"


def test_summary_actionable_issue_enters_summary_scope() -> None:
    state = ReviewState()
    state.global_review_history.append(
        GlobalReviewRecord(
            cycle=1,
            advisor_id="global_completeness",
            passed=False,
            feedback="summary table not synchronized",
            issues=[
                {
                    "id": "summary-sync",
                    "category": "report_completeness",
                    "target": "summary.md",
                    "required_action": "同步漏洞汇总表",
                    "actionable_by": "summary",
                }
            ],
        )
    )

    assert AtomicWorkflowEngine._classify_global_failure_scope(state) == "summary_or_ledger"
