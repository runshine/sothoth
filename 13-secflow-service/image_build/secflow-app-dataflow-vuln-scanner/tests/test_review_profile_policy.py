from __future__ import annotations

import copy
import json

import pytest

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtimes.pi_agent import PiAgentRuntime
from app.pi_vuln_core.config.models import EngineConfig
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.profile import (
    _MODEL_THINKING_LEVELS,
    get_review_profile_policy,
    get_review_score_threshold_policy,
    normalize_review_profile,
    resolve_profile_thinking,
)
from app.services.profile_templates import ProfileTemplateService
from app.pi_vuln_core.review.state import ReviewState
from run_vuln_scan import generate_config


def test_review_profiles_have_monotonic_execution_budgets() -> None:
    fast = get_review_profile_policy("fast")
    balanced = get_review_profile_policy("balanced")
    audit = get_review_profile_policy("audit")

    assert normalize_review_profile("strict") == "audit"
    assert fast.review_enabled is False
    assert balanced.review_enabled is True
    assert audit.review_enabled is True
    assert [fast.default_max_review_cycles, balanced.default_max_review_cycles, audit.default_max_review_cycles] == [1, 6, 10]
    assert fast.max_worker_turns_per_cycle < balanced.max_worker_turns_per_cycle < audit.max_worker_turns_per_cycle
    assert fast.worker_rpc_stdout_trace_bytes < balanced.worker_rpc_stdout_trace_bytes < audit.worker_rpc_stdout_trace_bytes
    assert [fast.worker_rpc_stdout_abort_bytes, balanced.worker_rpc_stdout_abort_bytes, audit.worker_rpc_stdout_abort_bytes] == [0, 0, 0]
    assert [fast.advisor_max_internal_turns, balanced.advisor_max_internal_turns, audit.advisor_max_internal_turns] == [0, 0, 0]
    assert fast.advisor_rpc_stdout_trace_bytes < balanced.advisor_rpc_stdout_trace_bytes < audit.advisor_rpc_stdout_trace_bytes
    assert [fast.advisor_rpc_stdout_abort_bytes, balanced.advisor_rpc_stdout_abort_bytes, audit.advisor_rpc_stdout_abort_bytes] == [0, 0, 0]
    assert [fast.reflection_passes_per_cycle, balanced.reflection_passes_per_cycle, audit.reflection_passes_per_cycle] == [1, 1, 1]
    assert [fast.reflection_max_internal_turns, balanced.reflection_max_internal_turns, audit.reflection_max_internal_turns] == [0, 0, 0]
    assert fast.reflection_rpc_stdout_trace_bytes < balanced.reflection_rpc_stdout_trace_bytes < audit.reflection_rpc_stdout_trace_bytes
    assert [fast.reflection_rpc_stdout_abort_bytes, balanced.reflection_rpc_stdout_abort_bytes, audit.reflection_rpc_stdout_abort_bytes] == [0, 0, 0]
    assert fast.min_evidence_artifacts < balanced.min_evidence_artifacts < audit.min_evidence_artifacts
    assert len(fast.required_pattern_families) < len(balanced.required_pattern_families) < len(audit.required_pattern_families)
    assert fast.min_declared_extraction_ratio < balanced.min_declared_extraction_ratio <= audit.min_declared_extraction_ratio
    assert balanced.required_risks == ("critical", "high")
    assert audit.required_risks == ("critical", "high", "medium")
    assert audit.required_kinds == ("star", "export", "used")
    assert audit.progress_required_after_cycle == 3
    assert audit.progress_no_signal_closure_streak == 1
    assert audit.progress_no_signal_abort_streak == 2


def test_review_profiles_have_monotonic_score_gates() -> None:
    fast_depth = get_review_score_threshold_policy("fast", "global_depth")
    balanced_depth = get_review_score_threshold_policy("balanced", "global_depth")
    audit_depth = get_review_score_threshold_policy("audit", "global_depth")
    assert (
        fast_depth.score_thresholds["code_evidence_depth"]
        < balanced_depth.score_thresholds["code_evidence_depth"]
        < audit_depth.score_thresholds["code_evidence_depth"]
    )
    assert get_review_score_threshold_policy("strict", "global_depth") == audit_depth

    fast_cmp = get_review_score_threshold_policy("fast", "global_completeness")
    balanced_cmp = get_review_score_threshold_policy("balanced", "global_completeness")
    audit_cmp = get_review_score_threshold_policy("audit", "global_completeness")
    assert (
        fast_cmp.score_thresholds["coverage"]
        < balanced_cmp.score_thresholds["coverage"]
        <= audit_cmp.score_thresholds["coverage"]
    )
    assert (
        fast_cmp.score_threshold_ramp_cycles
        < balanced_cmp.score_threshold_ramp_cycles
        < audit_cmp.score_threshold_ramp_cycles
    )


def test_profile_thinking_resolution_by_model_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    assert resolve_profile_thinking("openai/gpt-5.4", "fast") == "medium"
    assert resolve_profile_thinking("openai/gpt-5.4", "balanced") == "high"
    assert resolve_profile_thinking("openai/gpt-5.4", "audit") == "xhigh"

    assert resolve_profile_thinking("icsl/zai-org/GLM-5", "fast") == "medium"
    assert resolve_profile_thinking("icsl/zai-org/GLM-5", "balanced") == "high"
    assert resolve_profile_thinking("icsl/zai-org/GLM-5", "audit") == "xhigh"

    monkeypatch.setitem(_MODEL_THINKING_LEVELS, "mock/two", ("medium", "high"))
    monkeypatch.setitem(_MODEL_THINKING_LEVELS, "mock/one", ("high",))
    assert resolve_profile_thinking("mock/two", "fast") == "medium"
    assert resolve_profile_thinking("mock/two", "balanced") == "high"
    assert resolve_profile_thinking("mock/two", "audit") == "high"
    assert resolve_profile_thinking("mock/one", "fast") == "high"
    assert resolve_profile_thinking("mock/one", "balanced") == "high"
    assert resolve_profile_thinking("mock/one", "audit") == "high"
    assert resolve_profile_thinking("mock/none", "audit") == ""


def test_profile_thinking_resolution_reads_pi_models_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    models_json = tmp_path / "models.json"
    models_json.write_text(
        """
        {
          "providers": {
            "my_llm": {
              "models": [
                {"id": "MiniMax/MiniMax-M2.5", "reasoning": true}
              ]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("PI_MODELS_JSON", str(models_json))

    assert resolve_profile_thinking("my_llm/MiniMax/MiniMax-M2.5", "fast") == "medium"
    assert resolve_profile_thinking("my_llm/MiniMax/MiniMax-M2.5", "balanced") == "high"
    assert resolve_profile_thinking("my_llm/MiniMax/MiniMax-M2.5", "audit") == "xhigh"


def test_profile_thinking_resolution_uses_explicit_pi_models_json_levels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    models_json = tmp_path / "models.json"
    models_json.write_text(
        """
        {
          "providers": {
            "my_llm": {
              "models": [
                {
                  "id": "zai-org/GLM-5",
                  "reasoning": true,
                  "thinkingLevels": ["low", "medium", "high", "xhigh"]
                }
              ]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("PI_MODELS_JSON", str(models_json))

    assert resolve_profile_thinking("my_llm/zai-org/GLM-5", "fast") == "medium"
    assert resolve_profile_thinking("my_llm/zai-org/GLM-5", "balanced") == "high"
    assert resolve_profile_thinking("my_llm/zai-org/GLM-5", "audit") == "xhigh"


def test_profile_thinking_resolution_honors_pi_models_json_reasoning_false(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    models_json = tmp_path / "models.json"
    models_json.write_text(
        """
        {
          "providers": {
            "openai": {
              "models": [
                {"id": "gpt-5.4", "reasoning": false}
              ]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("PI_MODELS_JSON", str(models_json))

    assert resolve_profile_thinking("openai/gpt-5.4", "audit") == ""


def test_generate_config_uses_profile_default_budget_when_max_cycles_not_set(
    tmp_path,
) -> None:
    config = generate_config(
        run_dir=str(tmp_path / "run"),
        task_file=str(tmp_path / "task.md"),
        run_name="strict-run",
        model="openai/gpt-5.4",
        max_cycles=None,
        review_profile="strict",
    )
    engine = config["workflows"]["atomic"][0]["engine"]

    assert config["global"]["max_review_cycles"] == 10
    assert engine["max_review_cycles"] == 10
    assert engine["review_profile"] == "audit"
    assert engine["review_enabled"] is True
    worker_runtime = config["agents"][0]["runtime_config"]
    advisor_runtime = config["agents"][1]["runtime_config"]

    assert engine["max_worker_turns_per_cycle"] == get_review_profile_policy("audit").max_worker_turns_per_cycle
    assert engine["reflection_passes_per_cycle"] == 1
    assert engine["reflection_max_internal_turns"] == 0
    assert engine["reflection_rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").reflection_rpc_stdout_abort_bytes
    assert "reflection_max_wall_seconds" not in engine
    assert "reflection_no_progress_timeout_seconds" not in engine
    assert engine["min_discovery_cycles_before_pass"] == 3
    assert engine["progress_required_after_cycle"] == 3
    assert engine["plateau_closure_streak"] == 1
    assert engine["plateau_abort_streak"] == 2
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("audit").min_evidence_artifacts
    assert engine["required_pattern_families"] == list(get_review_profile_policy("audit").required_pattern_families)
    assert worker_runtime["max_internal_turns"] == 0
    assert worker_runtime["sdk_specific"]["thinking"] == "xhigh"
    assert advisor_runtime["sdk_specific"]["thinking"] == "xhigh"
    assert worker_runtime["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").worker_rpc_stdout_abort_bytes
    assert worker_runtime["api_max_retries"] == 0
    assert worker_runtime["pi_max_retries"] == 0
    assert "max_wall_seconds" not in worker_runtime
    assert "no_progress_timeout_seconds" not in worker_runtime
    assert "max_retry_wall_seconds" not in worker_runtime
    assert advisor_runtime["advisor_runtime_retries"] == 0
    assert advisor_runtime["max_internal_turns"] == 0
    assert advisor_runtime["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").advisor_rpc_stdout_abort_bytes
    assert advisor_runtime["api_max_retries"] == 0
    assert advisor_runtime["pi_max_retries"] == 0
    assert "max_wall_seconds" not in advisor_runtime
    assert "no_progress_timeout_seconds" not in advisor_runtime
    assert "max_retry_wall_seconds" not in advisor_runtime
    global_reviews = config["workflows"]["atomic"][0]["roles"]["advisors"]["global_review"]
    depth_review = next(item for item in global_reviews if item["instance_id"] == "global_depth")
    assert depth_review["score_thresholds"]["code_evidence_depth"] == 0.95
    assert depth_review["score_threshold_ramp_cycles"] == 8


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
    assert engine["max_worker_turns_per_cycle"] == get_review_profile_policy("audit").max_worker_turns_per_cycle
    assert engine["reflection_passes_per_cycle"] == 1
    assert "reflection_max_wall_seconds" not in engine
    assert "reflection_no_progress_timeout_seconds" not in engine
    assert engine["min_discovery_cycles_before_pass"] == 3
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("audit").min_evidence_artifacts
    assert "thinking" not in config["agents"][0]["runtime_config"]["sdk_specific"]
    assert "thinking" not in config["agents"][1]["runtime_config"]["sdk_specific"]


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
    assert completeness["score_fields"] == ["coverage"]
    assert completeness["score_thresholds"]["coverage"] == 1.00
    assert completeness["score_threshold_ramp_cycles"] == 8
    assert depth["score_thresholds"]["code_evidence_depth"] == 0.95
    assert config["agents"][0]["runtime_config"]["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").worker_rpc_stdout_abort_bytes
    assert config["agents"][1]["runtime_config"]["rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").advisor_rpc_stdout_abort_bytes
    assert config["agents"][1]["runtime_config"]["api_max_retries"] == 0
    assert config["agents"][1]["runtime_config"]["pi_max_retries"] == 0
    assert "max_wall_seconds" not in config["agents"][1]["runtime_config"]
    engine = config["workflows"]["atomic"][0]["engine"]
    assert engine["reflection_max_internal_turns"] == 0
    assert engine["reflection_rpc_stdout_abort_bytes"] == get_review_profile_policy("audit").reflection_rpc_stdout_abort_bytes
    assert "reflection_max_wall_seconds" not in engine
    assert engine["min_evidence_artifacts"] == get_review_profile_policy("audit").min_evidence_artifacts
    assert engine["required_pattern_families"] == list(get_review_profile_policy("audit").required_pattern_families)


def test_profile_template_preserves_zero_timeout_retry_interval() -> None:
    service = ProfileTemplateService()
    normalized, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "mock/model",
            "review_profile": "balanced",
            "timeout_max_retries": 2,
            "timeout_retry_interval_seconds": 0,
        },
    )

    assert normalized["timeout_retry_interval_seconds"] == 0
    for agent in config["agents"]:
        if agent.get("type") == "pi_agent":
            runtime = agent["runtime_config"]
            assert runtime["timeout_max_retries"] == 2
            assert runtime["timeout_retry_interval_seconds"] == 0
            assert runtime["timeout_retry_delay"] == 0


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
    assert config["global"]["max_review_cycles"] == 1
    assert engine["review_profile"] == "fast"
    assert engine["review_enabled"] is False
    assert engine["max_review_cycles"] == 1
    assert engine["reflection_passes_per_cycle"] == 1


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


def test_profile_template_runtime_overrides_cannot_bypass_thinking_policy() -> None:
    service = ProfileTemplateService()
    _, base_config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "icsl/zai-org/GLM-5",
            "thinking": "xhigh",
            "review_profile": "balanced",
        },
    )
    override_agents = copy.deepcopy(base_config["agents"])
    for agent in override_agents:
        agent.setdefault("runtime_config", {}).setdefault("sdk_specific", {})["thinking"] = "xhigh"

    normalized, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "icsl/zai-org/GLM-5",
            "thinking": "xhigh",
            "review_profile": "balanced",
        },
        runtime_overrides={"agents": override_agents},
    )

    worker_runtime = config["agents"][0]["runtime_config"]
    advisor_runtime = config["agents"][1]["runtime_config"]
    assert normalized["thinking"] == "high"
    assert worker_runtime["sdk_specific"]["thinking"] == "high"
    assert advisor_runtime["sdk_specific"]["thinking"] == "high"


def test_profile_template_runtime_overrides_cannot_lower_profile_runtime_budgets() -> None:
    service = ProfileTemplateService()
    _, base_config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "icsl/zai-org/GLM-5",
            "review_profile": "balanced",
        },
    )
    override_agents = copy.deepcopy(base_config["agents"])
    for agent in override_agents:
        runtime_config = agent.setdefault("runtime_config", {})
        runtime_config["max_internal_turns"] = 1
        runtime_config["rpc_stdout_abort_bytes"] = 6_710_886

    override_workflows = copy.deepcopy(base_config["workflows"])
    engine_override = override_workflows["atomic"][0]["engine"]
    engine_override["max_worker_turns_per_cycle"] = 1
    engine_override["reflection_max_internal_turns"] = 1
    engine_override["reflection_rpc_stdout_abort_bytes"] = 6_710_886

    _, config = service.compile_profile(
        template_kind="vuln_scan_default",
        config_payload={
            "model": "icsl/zai-org/GLM-5",
            "review_profile": "balanced",
        },
        runtime_overrides={
            "agents": override_agents,
            "workflows": override_workflows,
        },
    )

    policy = get_review_profile_policy("balanced")
    worker_runtime = config["agents"][0]["runtime_config"]
    advisor_runtime = config["agents"][1]["runtime_config"]
    engine = config["workflows"]["atomic"][0]["engine"]

    assert worker_runtime["max_internal_turns"] == 0
    assert worker_runtime["rpc_stdout_abort_bytes"] == policy.worker_rpc_stdout_abort_bytes
    assert advisor_runtime["max_internal_turns"] == 0
    assert advisor_runtime["rpc_stdout_abort_bytes"] == policy.advisor_rpc_stdout_abort_bytes
    assert engine["max_worker_turns_per_cycle"] == policy.max_worker_turns_per_cycle
    assert engine["reflection_max_internal_turns"] == 0
    assert engine["reflection_rpc_stdout_abort_bytes"] == policy.reflection_rpc_stdout_abort_bytes


def test_worker_reflection_stdout_abort_is_disabled_by_profile_even_for_stale_configs() -> None:
    wf_def = type(
        "WF",
        (),
        {
            "engine": EngineConfig(
                review_profile="balanced",
                reflection_rpc_stdout_abort_bytes=6_710_886,
            ),
        },
    )()
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file="task.md",
        working_dir="/tmp/work",
        review_profile="balanced",
    )

    limits = WorkerExecutor._effective_reflection_runtime_limits(wf_def, ctx)

    assert limits["rpc_stdout_abort_bytes"] == 0


def test_profile_gate_no_longer_requires_framework_artifacts(tmp_path) -> None:
    work_dir = tmp_path / "work"
    (work_dir / "_meta").mkdir(parents=True)
    (work_dir / "results").mkdir()
    (work_dir / "supporting_docs").mkdir()
    (work_dir / "summary.md").write_text(
        "# Summary\n\n只记录了内存安全和整数溢出，缺少其余模式族。\n",
        encoding="utf-8",
    )

    issues = GlobalReviewExecutor._profile_gate_issues(
        work_dir=str(work_dir),
        review_profile="audit",
    )

    assert issues == []


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

    issues = GlobalReviewExecutor._profile_gate_issues(
        work_dir=str(work_dir),
        review_profile="audit",
    )

    assert issues == []


@pytest.mark.asyncio
async def test_pi_worker_multi_turn_does_not_set_internal_turn_budget() -> None:
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

    assert runtime.captured_max_internal_turns is None


def test_strict_input_maps_to_audit_depth_budget() -> None:
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

    assert passed is False
    assert "profile_min_discovery_cycles" in feedback

    passed, feedback = atomic._apply_profile_min_discovery_gate(
        ctx=ctx,
        review_state=review_state,
        cycle=3,
        global_passed=True,
        global_feedback="",
        result_passed=True,
    )

    assert passed is True
    assert feedback == ""


def test_profile_min_discovery_gate_ignores_result_review_business_status() -> None:
    atomic = object.__new__(AtomicWorkflowEngine)
    atomic.wf = type(
        "WF",
        (),
        {"engine": EngineConfig(review_profile="balanced", min_discovery_cycles_before_pass=1)},
    )()
    ctx = WorkflowContext(
        workflow_id="wf",
        task_id="task",
        task_file="task.md",
        working_dir="/tmp/work",
        review_profile="balanced",
    )

    passed, feedback = atomic._apply_profile_min_discovery_gate(
        ctx=ctx,
        review_state=ReviewState(),
        cycle=1,
        global_passed=True,
        global_feedback="",
        result_passed=False,
    )

    assert passed is True
    assert feedback == ""
