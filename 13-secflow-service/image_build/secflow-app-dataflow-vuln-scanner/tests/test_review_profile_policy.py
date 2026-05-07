from __future__ import annotations

import json

import pytest

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtimes.pi_agent import PiAgentRuntime
from app.pi_vuln_core.config.models import EngineConfig
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.profile import (
    get_review_profile_policy,
    get_review_score_threshold_policy,
)
from app.services.profile_templates import ProfileTemplateService
from app.pi_vuln_core.review.state import ReviewState
from run_vuln_scan import generate_config


def test_review_profiles_have_monotonic_execution_budgets() -> None:
    fast = get_review_profile_policy("fast")
    balanced = get_review_profile_policy("balanced")
    strict = get_review_profile_policy("strict")
    audit = get_review_profile_policy("audit")

    assert [
        fast.default_max_review_cycles,
        balanced.default_max_review_cycles,
        strict.default_max_review_cycles,
        audit.default_max_review_cycles,
    ] == sorted([
        fast.default_max_review_cycles,
        balanced.default_max_review_cycles,
        strict.default_max_review_cycles,
        audit.default_max_review_cycles,
    ])
    assert fast.max_worker_turns_per_cycle < balanced.max_worker_turns_per_cycle < strict.max_worker_turns_per_cycle < audit.max_worker_turns_per_cycle
    assert fast.worker_max_wall_seconds < balanced.worker_max_wall_seconds < strict.worker_max_wall_seconds < audit.worker_max_wall_seconds
    assert fast.worker_no_progress_timeout_seconds < balanced.worker_no_progress_timeout_seconds < strict.worker_no_progress_timeout_seconds < audit.worker_no_progress_timeout_seconds
    assert fast.worker_rpc_stdout_abort_bytes < balanced.worker_rpc_stdout_abort_bytes < strict.worker_rpc_stdout_abort_bytes < audit.worker_rpc_stdout_abort_bytes
    assert fast.advisor_max_internal_turns < balanced.advisor_max_internal_turns < strict.advisor_max_internal_turns < audit.advisor_max_internal_turns
    assert fast.advisor_max_wall_seconds < balanced.advisor_max_wall_seconds < strict.advisor_max_wall_seconds < audit.advisor_max_wall_seconds
    assert fast.advisor_no_progress_timeout_seconds < balanced.advisor_no_progress_timeout_seconds < strict.advisor_no_progress_timeout_seconds < audit.advisor_no_progress_timeout_seconds
    assert fast.advisor_rpc_stdout_abort_bytes < balanced.advisor_rpc_stdout_abort_bytes < strict.advisor_rpc_stdout_abort_bytes < audit.advisor_rpc_stdout_abort_bytes
    assert fast.reflection_passes_per_cycle < balanced.reflection_passes_per_cycle < strict.reflection_passes_per_cycle < audit.reflection_passes_per_cycle
    assert fast.reflection_max_internal_turns < balanced.reflection_max_internal_turns < strict.reflection_max_internal_turns < audit.reflection_max_internal_turns
    assert fast.reflection_max_wall_seconds < balanced.reflection_max_wall_seconds < strict.reflection_max_wall_seconds < audit.reflection_max_wall_seconds
    assert fast.reflection_rpc_stdout_abort_bytes < balanced.reflection_rpc_stdout_abort_bytes < strict.reflection_rpc_stdout_abort_bytes < audit.reflection_rpc_stdout_abort_bytes
    assert fast.min_evidence_artifacts < balanced.min_evidence_artifacts < strict.min_evidence_artifacts < audit.min_evidence_artifacts
    assert len(fast.required_pattern_families) < len(balanced.required_pattern_families) < len(strict.required_pattern_families) < len(audit.required_pattern_families)
    assert fast.min_declared_extraction_ratio < balanced.min_declared_extraction_ratio < strict.min_declared_extraction_ratio <= audit.min_declared_extraction_ratio
    assert balanced.required_risks == ("critical", "high")
    assert strict.required_risks == ("critical", "high", "medium")
    assert audit.required_kinds == ("input", "export", "used", "cleaned", "star")


def test_review_profiles_have_monotonic_score_gates() -> None:
    fast_depth = get_review_score_threshold_policy("fast", "global_depth")
    balanced_depth = get_review_score_threshold_policy("balanced", "global_depth")
    strict_depth = get_review_score_threshold_policy("strict", "global_depth")
    audit_depth = get_review_score_threshold_policy("audit", "global_depth")
    assert (
        fast_depth.score_thresholds["code_evidence_depth"]
        < balanced_depth.score_thresholds["code_evidence_depth"]
        < strict_depth.score_thresholds["code_evidence_depth"]
        < audit_depth.score_thresholds["code_evidence_depth"]
    )

    fast_cmp = get_review_score_threshold_policy("fast", "global_completeness")
    balanced_cmp = get_review_score_threshold_policy("balanced", "global_completeness")
    strict_cmp = get_review_score_threshold_policy("strict", "global_completeness")
    audit_cmp = get_review_score_threshold_policy("audit", "global_completeness")
    assert (
        fast_cmp.score_thresholds["export_followthrough"]
        < balanced_cmp.score_thresholds["export_followthrough"]
        < strict_cmp.score_thresholds["export_followthrough"]
        <= audit_cmp.score_thresholds["export_followthrough"]
    )
    assert (
        fast_cmp.score_threshold_ramp_cycles
        < balanced_cmp.score_threshold_ramp_cycles
        < strict_cmp.score_threshold_ramp_cycles
        < audit_cmp.score_threshold_ramp_cycles
    )


def test_generate_config_uses_profile_default_budget_when_max_cycles_not_set(
    tmp_path,
) -> None:
    config = generate_config(
        run_dir=str(tmp_path / "run"),
        task_file=str(tmp_path / "task.md"),
        run_name="strict-run",
        model="mock/model",
        max_cycles=None,
        review_profile="strict",
    )
    engine = config["workflows"]["atomic"][0]["engine"]

    assert config["global"]["max_review_cycles"] == 8
    assert engine["max_review_cycles"] == 8
    assert engine["review_profile"] == "strict"
    worker_runtime = config["agents"][0]["runtime_config"]
    advisor_runtime = config["agents"][1]["runtime_config"]

    assert engine["max_worker_turns_per_cycle"] == 100
    assert engine["reflection_passes_per_cycle"] == 2
    assert engine["reflection_max_internal_turns"] == get_review_profile_policy("strict").reflection_max_internal_turns
    assert engine["reflection_max_wall_seconds"] == get_review_profile_policy("strict").reflection_max_wall_seconds
    assert engine["reflection_rpc_stdout_abort_bytes"] == get_review_profile_policy("strict").reflection_rpc_stdout_abort_bytes
    assert engine["min_discovery_cycles_before_pass"] == 2
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("strict").min_evidence_artifacts
    assert engine["required_pattern_families"] == list(get_review_profile_policy("strict").required_pattern_families)
    assert worker_runtime["max_internal_turns"] == 100
    assert worker_runtime["max_wall_seconds"] == get_review_profile_policy("strict").worker_max_wall_seconds
    assert worker_runtime["rpc_stdout_abort_bytes"] == get_review_profile_policy("strict").worker_rpc_stdout_abort_bytes
    assert advisor_runtime["advisor_runtime_retries"] == 3
    assert advisor_runtime["max_internal_turns"] == get_review_profile_policy("strict").advisor_max_internal_turns
    assert advisor_runtime["max_wall_seconds"] == get_review_profile_policy("strict").advisor_max_wall_seconds
    assert advisor_runtime["rpc_stdout_abort_bytes"] == get_review_profile_policy("strict").advisor_rpc_stdout_abort_bytes
    global_reviews = config["workflows"]["atomic"][0]["roles"]["advisors"]["global_review"]
    depth_review = next(item for item in global_reviews if item["instance_id"] == "global_depth")
    assert depth_review["score_thresholds"]["code_evidence_depth"] == 0.90
    assert depth_review["score_threshold_ramp_cycles"] == 6


def test_generate_config_respects_explicit_cycles_but_keeps_profile_depth_budget(
    tmp_path,
) -> None:
    config = generate_config(
        run_dir=str(tmp_path / "run"),
        task_file=str(tmp_path / "task.md"),
        run_name="audit-run",
        model="mock/model",
        max_cycles=4,
        review_profile="audit",
    )
    engine = config["workflows"]["atomic"][0]["engine"]

    assert config["global"]["max_review_cycles"] == 4
    assert engine["max_review_cycles"] == 4
    assert engine["max_worker_turns_per_cycle"] == 140
    assert engine["reflection_passes_per_cycle"] == 3
    assert engine["reflection_max_wall_seconds"] == get_review_profile_policy("audit").reflection_max_wall_seconds
    assert engine["min_discovery_cycles_before_pass"] == 3
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("audit").min_evidence_artifacts


def test_profile_template_compilation_applies_score_gates() -> None:
    service = ProfileTemplateService()
    _, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "mock/model",
            "thinking": "high",
            "review_profile": "audit",
        },
    )

    global_reviews = config["workflows"]["atomic"][0]["roles"]["advisors"]["global_review"]
    completeness = next(item for item in global_reviews if item["instance_id"] == "global_completeness")
    depth = next(item for item in global_reviews if item["instance_id"] == "global_depth")
    assert completeness["score_thresholds"]["export_followthrough"] == 1.00
    assert completeness["score_threshold_ramp_cycles"] == 8
    assert depth["score_thresholds"]["code_evidence_depth"] == 0.95
    assert config["agents"][1]["runtime_config"]["max_wall_seconds"] == 1800
    assert config["agents"][0]["runtime_config"]["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").worker_rpc_stdout_abort_bytes
    assert config["agents"][1]["runtime_config"]["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").advisor_rpc_stdout_abort_bytes
    engine = config["workflows"]["atomic"][0]["engine"]
    assert engine["reflection_max_internal_turns"] == get_review_profile_policy("audit").reflection_max_internal_turns
    assert engine["reflection_rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").reflection_rpc_stdout_abort_bytes
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("audit").min_evidence_artifacts
    assert engine["required_pattern_families"] == list(get_review_profile_policy("audit").required_pattern_families)


def test_profile_template_compilation_syncs_review_cycles_to_engine() -> None:
    service = ProfileTemplateService()
    _, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "mock/model",
            "thinking": "high",
            "review_profile": "fast",
            "max_review_cycles": 3,
        },
    )

    engine = config["workflows"]["atomic"][0]["engine"]
    assert config["global"]["max_review_cycles"] == 3
    assert engine["review_profile"] == "fast"
    assert engine["max_review_cycles"] == 3


def test_profile_template_runtime_global_cycles_reach_engine() -> None:
    service = ProfileTemplateService()
    _, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "mock/model",
            "thinking": "high",
            "review_profile": "balanced",
        },
        runtime_overrides={"global": {"max_review_cycles": 4}},
    )

    engine = config["workflows"]["atomic"][0]["engine"]
    assert config["global"]["max_review_cycles"] == 4
    assert engine["max_review_cycles"] == 4


def test_profile_gate_requires_artifacts_and_pattern_family_evidence(tmp_path) -> None:
    work_dir = tmp_path / "work"
    (work_dir / "_meta").mkdir(parents=True)
    (work_dir / "results").mkdir()
    (work_dir / "supporting_docs").mkdir()
    (work_dir / "summary.md").write_text(
        "# Summary\n\n只记录了内存安全和整数溢出，缺少其余模式族。\n",
        encoding="utf-8",
    )
    (work_dir / "_meta" / "coverage_ledger.json").write_text(
        json.dumps({
            "coverage_obligations": {
                "total": 1,
                "entries": [{
                    "id": "USED:test",
                    "kind": "used",
                    "risk": "low",
                    "status": "documented",
                    "documented": True,
                    "evidence_sources": ["supporting_docs/evidence_1.md"],
                }],
                "open_entries": [],
                "quality": {
                    "declared_counts": {},
                    "declared_total": 1,
                    "extracted_total": 1,
                },
            },
        }),
        encoding="utf-8",
    )

    issues = GlobalReviewExecutor._profile_gate_issues(
        work_dir=str(work_dir),
        review_profile="audit",
    )

    assert any(item["blocking_type"] == "profile_evidence_floor" for item in issues)
    assert any(item["blocking_type"] == "profile_pattern_family_gap" for item in issues)


def test_profile_gate_accepts_required_pattern_family_evidence(tmp_path) -> None:
    work_dir = tmp_path / "work"
    (work_dir / "_meta").mkdir(parents=True)
    (work_dir / "results").mkdir()
    (work_dir / "supporting_docs").mkdir()
    (work_dir / "summary.md").write_text(
        "# Summary\n\n"
        "内存安全、整数截断、输入校验绕过、逻辑状态机、资源生命周期、并发 TOCTOU 均已记录。\n",
        encoding="utf-8",
    )
    for idx in range(1, 6):
        (work_dir / "supporting_docs" / f"evidence_{idx}.md").write_text(
            "源码级负面证据：边界值、状态机、资源释放与 race/timing not_applicable。\n",
            encoding="utf-8",
        )
    (work_dir / "_meta" / "coverage_ledger.json").write_text(
        json.dumps({
            "coverage_obligations": {
                "total": 1,
                "entries": [{
                    "id": "USED:test",
                    "kind": "used",
                    "risk": "low",
                    "status": "documented",
                    "documented": True,
                    "evidence_sources": ["supporting_docs/evidence_1.md"],
                }],
                "open_entries": [],
                "quality": {
                    "declared_counts": {},
                    "declared_total": 1,
                    "extracted_total": 1,
                },
            },
        }),
        encoding="utf-8",
    )

    issues = GlobalReviewExecutor._profile_gate_issues(
        work_dir=str(work_dir),
        review_profile="audit",
    )

    assert issues == []


@pytest.mark.asyncio
async def test_pi_worker_multi_turn_uses_internal_turn_budget() -> None:
    class CapturingRuntime(PiAgentRuntime):
        captured_max_internal_turns: int | None = None

        async def send_message(self, *args, max_internal_turns=None, **kwargs):  # type: ignore[override]
            self.captured_max_internal_turns = max_internal_turns
            return AgentResponse(content="", finished=True)

    runtime = CapturingRuntime({
        "id": "pi-worker",
        "name": "Pi Worker",
        "type": "pi_agent",
        "runtime_config": {},
    })

    await runtime.multi_turn_execute(
        system_prompt="sys",
        user_prompt="user",
        working_dir="/tmp/work",
        max_turns=73,
        session_id="worker-cycle-001",
    )

    assert runtime.captured_max_internal_turns == 73


def test_strict_profile_does_not_allow_first_cycle_early_exit() -> None:
    atomic = object.__new__(AtomicWorkflowEngine)
    atomic.wf = type("WF", (), {"engine": EngineConfig(review_profile="strict")})()
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file="task.md",
        working_dir="/tmp/work",
        review_profile="strict",
    )
    review_state = ReviewState()

    passed, feedback = atomic._apply_profile_min_discovery_gate(
        ctx=ctx,
        review_state=review_state,
        cycle=1,
        global_passed=True,
        global_feedback="",
        result_passed=True,
    )

    assert passed is False
    assert "profile_min_discovery_cycles" in feedback
    assert review_state.get_recent_issues(last_n=1)[0]["blocking_type"] == "profile_depth_budget"

    passed, feedback = atomic._apply_profile_min_discovery_gate(
        ctx=ctx,
        review_state=review_state,
        cycle=2,
        global_passed=True,
        global_feedback="",
        result_passed=True,
    )

    assert passed is True
    assert feedback == ""
