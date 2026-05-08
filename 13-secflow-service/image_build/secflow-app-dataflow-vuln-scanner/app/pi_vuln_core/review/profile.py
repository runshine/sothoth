from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ReviewProfileName = Literal["fast", "balanced", "audit"]
ThinkingLevel = Literal["low", "medium", "high", "xhigh"]


@dataclass(frozen=True)
class ReviewProfilePolicy:
    name: ReviewProfileName
    description: str
    review_enabled: bool
    enforce_coverage_gate: bool
    require_dataflow_extraction: bool
    required_risks: tuple[str, ...]
    required_kinds: tuple[str, ...]
    min_declared_extraction_ratio: float
    allow_summary_only_evidence: bool
    default_max_review_cycles: int
    max_worker_turns_per_cycle: int
    reflection_passes_per_cycle: int
    reflection_max_internal_turns: int
    reflection_rpc_stdout_trace_bytes: int
    reflection_rpc_stdout_abort_bytes: int
    min_discovery_cycles_before_pass: int
    progress_required_after_cycle: int
    progress_no_signal_closure_streak: int
    progress_no_signal_abort_streak: int
    min_evidence_artifacts: int
    required_pattern_families: tuple[str, ...]
    max_open_obligations_in_worker_prompt: int
    worker_rpc_stdout_trace_bytes: int
    worker_rpc_stdout_abort_bytes: int
    advisor_max_internal_turns: int
    advisor_rpc_stdout_trace_bytes: int
    advisor_rpc_stdout_abort_bytes: int
    execution_goal: str
    closure_policy: str
    depth_lanes: tuple[str, ...]


@dataclass(frozen=True)
class ReviewScoreThresholdPolicy:
    score_fields: tuple[str, ...]
    score_thresholds_start: dict[str, float]
    score_thresholds: dict[str, float]
    score_threshold_ramp_cycles: int


_THINKING_LEVEL_ORDER: tuple[ThinkingLevel, ...] = ("low", "medium", "high", "xhigh")

_MODEL_THINKING_LEVELS: dict[str, tuple[ThinkingLevel, ...]] = {
    "icsl/zai-org/glm-5": ("low", "medium", "high"),
}

_MODEL_PREFIX_THINKING_LEVELS: tuple[tuple[str, tuple[ThinkingLevel, ...]], ...] = (
    ("openai/gpt-", ("low", "medium", "high", "xhigh")),
    ("anthropic/", ("low", "medium", "high", "xhigh")),
)


_PROFILE_POLICIES: dict[str, ReviewProfilePolicy] = {
    "fast": ReviewProfilePolicy(
        name="fast",
        description="快速筛选：单轮 Worker 分析与 summary 输出，不启动评审闭环。",
        review_enabled=False,
        enforce_coverage_gate=False,
        require_dataflow_extraction=False,
        required_risks=(),
        required_kinds=(),
        min_declared_extraction_ratio=0.0,
        allow_summary_only_evidence=True,
        default_max_review_cycles=1,
        max_worker_turns_per_cycle=80,
        reflection_passes_per_cycle=0,
        reflection_max_internal_turns=0,
        reflection_rpc_stdout_trace_bytes=512 * 1024,
        reflection_rpc_stdout_abort_bytes=16 * 1024 * 1024,
        min_discovery_cycles_before_pass=1,
        progress_required_after_cycle=0,
        progress_no_signal_closure_streak=1,
        progress_no_signal_abort_streak=1,
        min_evidence_artifacts=0,
        required_pattern_families=(),
        max_open_obligations_in_worker_prompt=8,
        worker_rpc_stdout_trace_bytes=2 * 1024 * 1024,
        worker_rpc_stdout_abort_bytes=96 * 1024 * 1024,
        advisor_max_internal_turns=0,
        advisor_rpc_stdout_trace_bytes=1 * 1024 * 1024,
        advisor_rpc_stdout_abort_bytes=64 * 1024 * 1024,
        execution_goal="快速确认显性漏洞并生成 summary.md；不做评审返工或低风险穷尽。",
        closure_policy="fast 不进入评审 closure；summary.md 必须由 Worker 真实生成。",
        depth_lanes=(
            "沿数据流主路径核对显性内存安全/整数安全问题",
            "优先验证 STAR 与最直接 USED 终点",
        ),
    ),
    "balanced": ReviewProfilePolicy(
        name="balanced",
        description="平衡档：面向中高危与关键路径，目标是挖到大部分主要漏洞。",
        review_enabled=True,
        enforce_coverage_gate=True,
        require_dataflow_extraction=True,
        required_risks=("critical", "high"),
        required_kinds=("star",),
        min_declared_extraction_ratio=0.50,
        allow_summary_only_evidence=True,
        default_max_review_cycles=6,
        max_worker_turns_per_cycle=140,
        reflection_passes_per_cycle=1,
        reflection_max_internal_turns=0,
        reflection_rpc_stdout_trace_bytes=1 * 1024 * 1024,
        reflection_rpc_stdout_abort_bytes=128 * 1024 * 1024,
        min_discovery_cycles_before_pass=1,
        progress_required_after_cycle=0,
        progress_no_signal_closure_streak=2,
        progress_no_signal_abort_streak=3,
        min_evidence_artifacts=1,
        required_pattern_families=(
            "memory_safety",
            "integer_safety",
            "input_validation",
        ),
        max_open_obligations_in_worker_prompt=24,
        worker_rpc_stdout_trace_bytes=4 * 1024 * 1024,
        worker_rpc_stdout_abort_bytes=256 * 1024 * 1024,
        advisor_max_internal_turns=0,
        advisor_rpc_stdout_trace_bytes=4 * 1024 * 1024,
        advisor_rpc_stdout_abort_bytes=128 * 1024 * 1024,
        execution_goal="覆盖 STAR、高风险端点和关键 EXPORT/USED，优先挖出大部分中高危漏洞。",
        closure_policy="closure 只验证 active backlog、STAR 和高风险 open obligations，不重新无限发散。",
        depth_lanes=(
            "主入口到 packet/mbuf 解析链的输入可控性复核",
            "STAR/高风险 EXPORT 下游继续跟入",
            "USED 终点的长度、索引、拷贝、裁剪和校验绕过扫描",
            "对未立项的高风险端点记录 source_closed 或 accepted_residual",
        ),
    ),
    "audit": ReviewProfilePolicy(
        name="audit",
        description="审计档：深度漏洞挖掘，追求最多、最深且可复核的漏洞证据。",
        review_enabled=True,
        enforce_coverage_gate=True,
        require_dataflow_extraction=True,
        required_risks=("critical", "high", "medium"),
        required_kinds=("star", "export", "used"),
        min_declared_extraction_ratio=1.00,
        allow_summary_only_evidence=False,
        default_max_review_cycles=10,
        max_worker_turns_per_cycle=260,
        reflection_passes_per_cycle=3,
        reflection_max_internal_turns=0,
        reflection_rpc_stdout_trace_bytes=2 * 1024 * 1024,
        reflection_rpc_stdout_abort_bytes=256 * 1024 * 1024,
        min_discovery_cycles_before_pass=3,
        progress_required_after_cycle=3,
        progress_no_signal_closure_streak=1,
        progress_no_signal_abort_streak=2,
        min_evidence_artifacts=5,
        required_pattern_families=(
            "memory_safety",
            "integer_safety",
            "input_validation",
            "logic_state",
            "resource_lifetime",
            "concurrency_timing",
        ),
        max_open_obligations_in_worker_prompt=80,
        worker_rpc_stdout_trace_bytes=8 * 1024 * 1024,
        worker_rpc_stdout_abort_bytes=512 * 1024 * 1024,
        advisor_max_internal_turns=0,
        advisor_rpc_stdout_trace_bytes=8 * 1024 * 1024,
        advisor_rpc_stdout_abort_bytes=256 * 1024 * 1024,
        execution_goal="深度审计关键数据流、变体和跨路径副作用；尽量挖出最多且最深的漏洞。",
        closure_policy="closure 优先验证 active backlog 与关键 obligations；无有效进展时收敛，external_blocked 必须显式保留。",
        depth_lanes=(
            "balanced 全部路线",
            "STAR/EXPORT/USED obligation 深度闭环，并对 INPUT/CLEANED 保留可复核边界",
            "跨函数、跨协议族、跨方向的漏洞变体搜索",
            "未立项端点的可复核负证据矩阵",
            "可利用性前提、攻击者能力、配置依赖和 residual 边界审计",
            "对候选漏洞做反例/误报证伪后再保留最终报告",
        ),
    ),
}


_COMPLETENESS_SCORE_FIELDS = (
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "limitations_honesty",
    "report_completeness",
)
_DEPTH_SCORE_FIELDS = (
    "vuln_pattern_breadth",
    "code_evidence_depth",
)


_SCORE_THRESHOLD_POLICIES: dict[str, dict[str, ReviewScoreThresholdPolicy]] = {
    "fast": {
        "global_completeness": ReviewScoreThresholdPolicy(
            score_fields=_COMPLETENESS_SCORE_FIELDS,
            score_thresholds_start={
                "input_coverage": 0.45,
                "export_followthrough": 0.35,
                "used_coverage": 0.35,
                "limitations_honesty": 0.45,
                "report_completeness": 0.45,
            },
            score_thresholds={
                "input_coverage": 0.70,
                "export_followthrough": 0.55,
                "used_coverage": 0.55,
                "limitations_honesty": 0.65,
                "report_completeness": 0.60,
            },
            score_threshold_ramp_cycles=2,
        ),
        "global_depth": ReviewScoreThresholdPolicy(
            score_fields=_DEPTH_SCORE_FIELDS,
            score_thresholds_start={
                "vuln_pattern_breadth": 0.35,
                "code_evidence_depth": 0.45,
            },
            score_thresholds={
                "vuln_pattern_breadth": 0.55,
                "code_evidence_depth": 0.65,
            },
            score_threshold_ramp_cycles=2,
        ),
    },
    "balanced": {
        "global_completeness": ReviewScoreThresholdPolicy(
            score_fields=_COMPLETENESS_SCORE_FIELDS,
            score_thresholds_start={
                "input_coverage": 0.80,
                "export_followthrough": 0.70,
                "used_coverage": 0.70,
                "limitations_honesty": 0.75,
                "report_completeness": 0.70,
            },
            score_thresholds={
                "input_coverage": 0.95,
                "export_followthrough": 0.90,
                "used_coverage": 0.90,
                "limitations_honesty": 0.90,
                "report_completeness": 0.88,
            },
            score_threshold_ramp_cycles=5,
        ),
        "global_depth": ReviewScoreThresholdPolicy(
            score_fields=_DEPTH_SCORE_FIELDS,
            score_thresholds_start={
                "vuln_pattern_breadth": 0.60,
                "code_evidence_depth": 0.60,
            },
            score_thresholds={
                "vuln_pattern_breadth": 0.82,
                "code_evidence_depth": 0.82,
            },
            score_threshold_ramp_cycles=5,
        ),
    },
    "audit": {
        "global_completeness": ReviewScoreThresholdPolicy(
            score_fields=_COMPLETENESS_SCORE_FIELDS,
            score_thresholds_start={
                "input_coverage": 0.90,
                "export_followthrough": 0.85,
                "used_coverage": 0.85,
                "limitations_honesty": 0.85,
                "report_completeness": 0.80,
            },
            score_thresholds={
                "input_coverage": 1.00,
                "export_followthrough": 1.00,
                "used_coverage": 1.00,
                "limitations_honesty": 0.99,
                "report_completeness": 0.98,
            },
            score_threshold_ramp_cycles=8,
        ),
        "global_depth": ReviewScoreThresholdPolicy(
            score_fields=_DEPTH_SCORE_FIELDS,
            score_thresholds_start={
                "vuln_pattern_breadth": 0.75,
                "code_evidence_depth": 0.75,
            },
            score_thresholds={
                "vuln_pattern_breadth": 0.95,
                "code_evidence_depth": 0.95,
            },
            score_threshold_ramp_cycles=8,
        ),
    },
}


def normalize_review_profile(value: str | None) -> ReviewProfileName:
    name = str(value or "balanced").strip().lower()
    if name == "strict":
        return "audit"
    if name not in _PROFILE_POLICIES:
        return "balanced"
    return name  # type: ignore[return-value]


def get_review_profile_policy(value: str | None) -> ReviewProfilePolicy:
    return _PROFILE_POLICIES[normalize_review_profile(value)]


def supported_thinking_levels_for_model(model: str | None) -> tuple[ThinkingLevel, ...]:
    normalized = str(model or "").strip().lower()
    if not normalized:
        return ()
    if normalized in _MODEL_THINKING_LEVELS:
        return _MODEL_THINKING_LEVELS[normalized]
    for prefix, levels in _MODEL_PREFIX_THINKING_LEVELS:
        if normalized.startswith(prefix):
            return levels
    return ()


def resolve_profile_thinking(model: str | None, review_profile: str | None) -> str:
    supported = set(supported_thinking_levels_for_model(model))
    levels = [level for level in _THINKING_LEVEL_ORDER if level in supported]
    if not levels:
        return ""

    profile = normalize_review_profile(review_profile)
    if len(levels) >= 4:
        profile_index = {"fast": -3, "balanced": -2, "audit": -1}[profile]
    elif len(levels) >= 3:
        profile_index = {"fast": -3, "balanced": -2, "audit": -1}[profile]
    elif len(levels) == 2:
        profile_index = {"fast": 0, "balanced": 1, "audit": 1}[profile]
    else:
        profile_index = 0
    return levels[profile_index]


def apply_profile_thinking_to_runtime_config(
    runtime_config: dict,
    review_profile: str | None,
) -> str:
    thinking = resolve_profile_thinking(runtime_config.get("model"), review_profile)
    sdk_specific = runtime_config.setdefault("sdk_specific", {})
    if thinking:
        sdk_specific["thinking"] = thinking
    else:
        sdk_specific.pop("thinking", None)
    return thinking


def apply_profile_thinking_to_config(config: dict, review_profile: str | None) -> None:
    for agent in config.get("agents") or []:
        if not isinstance(agent, dict):
            continue
        runtime_config = agent.get("runtime_config")
        if isinstance(runtime_config, dict):
            apply_profile_thinking_to_runtime_config(runtime_config, review_profile)


def get_review_score_threshold_policy(
    value: str | None,
    advisor_id: str,
) -> ReviewScoreThresholdPolicy:
    profile_name = normalize_review_profile(value)
    normalized_advisor = str(advisor_id or "").strip().lower()
    if normalized_advisor in {"completeness", "global_completeness"}:
        normalized_advisor = "global_completeness"
    elif normalized_advisor in {"depth", "global_depth"}:
        normalized_advisor = "global_depth"
    elif "depth" in normalized_advisor:
        normalized_advisor = "global_depth"
    else:
        normalized_advisor = "global_completeness"
    policy = _SCORE_THRESHOLD_POLICIES[profile_name][normalized_advisor]
    return ReviewScoreThresholdPolicy(
        score_fields=tuple(policy.score_fields),
        score_thresholds_start=dict(policy.score_thresholds_start),
        score_thresholds=dict(policy.score_thresholds),
        score_threshold_ramp_cycles=policy.score_threshold_ramp_cycles,
    )


def _runtime_config_dict(agent: dict) -> dict:
    runtime_config = agent.get("runtime_config")
    if not isinstance(runtime_config, dict):
        runtime_config = {}
        agent["runtime_config"] = runtime_config
    return runtime_config


_RPC_RUNTIME_WATCHDOG_KEYS = (
    "no_progress_timeout_seconds",
    "max_wall_seconds",
    "max_retry_wall_seconds",
)

_RPC_REFLECTION_WATCHDOG_KEYS = (
    "reflection_no_progress_timeout_seconds",
    "reflection_max_wall_seconds",
)


def _coerce_min_int(value: Any, default: int, minimum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def _runtime_transport(runtime_config: dict[str, Any]) -> str:
    transport = str(runtime_config.get("transport") or runtime_config.get("mode") or "json").strip().lower()
    return transport if transport in {"json", "rpc"} else "json"


def _sanitize_rpc_runtime_config(runtime_config: dict[str, Any]) -> None:
    timeout_max_retries = _coerce_min_int(runtime_config.get("timeout_max_retries", 3), 3, 1)
    timeout_retry_interval_seconds = _coerce_min_int(
        runtime_config.get(
            "timeout_retry_interval_seconds",
            runtime_config.get("timeout_retry_delay", 30),
        ),
        30,
        0,
    )
    runtime_config["timeout_max_retries"] = timeout_max_retries
    runtime_config["timeout_retry_delay"] = timeout_retry_interval_seconds
    runtime_config["timeout_retry_interval_seconds"] = timeout_retry_interval_seconds
    if _runtime_transport(runtime_config) != "rpc":
        return
    for key in _RPC_RUNTIME_WATCHDOG_KEYS:
        runtime_config.pop(key, None)
    runtime_config["api_max_retries"] = _coerce_min_int(
        runtime_config.get("api_max_retries", runtime_config.get("max_retries", 0)),
        0,
        0,
    )
    runtime_config["pi_max_retries"] = _coerce_min_int(
        runtime_config.get("pi_max_retries", 0),
        0,
        0,
    )


def apply_profile_runtime_policy_to_config(
    config: dict,
    review_profile: str | None,
) -> ReviewProfileName:
    """Re-apply profile-owned runtime budgets after external overrides."""
    policy = get_review_profile_policy(review_profile)
    if not policy.review_enabled:
        config.setdefault("global", {})["max_review_cycles"] = 1

    for agent in config.get("agents") or []:
        if not isinstance(agent, dict):
            continue
        runtime_config = _runtime_config_dict(agent)
        agent_type = str(agent.get("type") or "").strip()
        if agent_type == "pi_agent":
            _sanitize_rpc_runtime_config(runtime_config)
        agent_id = str(agent.get("id") or "").strip()
        if agent_id == "pi-worker":
            runtime_config["max_internal_turns"] = 0
            runtime_config["rpc_stdout_trace_bytes"] = policy.worker_rpc_stdout_trace_bytes
            runtime_config["rpc_stdout_abort_bytes"] = policy.worker_rpc_stdout_abort_bytes
        elif agent_id == "pi-advisor":
            runtime_config["advisor_runtime_retries"] = 3
            runtime_config["max_internal_turns"] = 0
            runtime_config["rpc_stdout_trace_bytes"] = policy.advisor_rpc_stdout_trace_bytes
            runtime_config["rpc_stdout_abort_bytes"] = policy.advisor_rpc_stdout_abort_bytes

    atomic_workflows = ((config.get("workflows") or {}).get("atomic") or [])
    for workflow in atomic_workflows:
        if not isinstance(workflow, dict):
            continue
        engine = workflow.get("engine")
        if not isinstance(engine, dict):
            engine = {}
            workflow["engine"] = engine
        if "review_profile" not in engine and workflow.get("id") != "vuln_scan":
            continue
        engine["review_profile"] = policy.name
        engine["review_enabled"] = policy.review_enabled
        if not policy.review_enabled:
            engine["max_review_cycles"] = 1
        engine["max_worker_turns_per_cycle"] = policy.max_worker_turns_per_cycle
        engine["reflection_passes_per_cycle"] = policy.reflection_passes_per_cycle
        engine["reflection_max_internal_turns"] = 0
        engine["reflection_rpc_stdout_trace_bytes"] = policy.reflection_rpc_stdout_trace_bytes
        engine["reflection_rpc_stdout_abort_bytes"] = policy.reflection_rpc_stdout_abort_bytes
        for key in _RPC_REFLECTION_WATCHDOG_KEYS:
            engine.pop(key, None)
        engine["min_discovery_cycles_before_pass"] = policy.min_discovery_cycles_before_pass
        engine["progress_required_after_cycle"] = policy.progress_required_after_cycle
        engine["progress_no_signal_closure_streak"] = policy.progress_no_signal_closure_streak
        engine["progress_no_signal_abort_streak"] = policy.progress_no_signal_abort_streak
        engine["min_evidence_artifacts"] = policy.min_evidence_artifacts
        engine["required_pattern_families"] = list(policy.required_pattern_families)
        engine["plateau_closure_streak"] = policy.progress_no_signal_closure_streak
        engine["plateau_abort_streak"] = policy.progress_no_signal_abort_streak

        advisors = ((workflow.get("roles") or {}).get("advisors") or {})
        for advisor in advisors.get("global_review") or []:
            if not isinstance(advisor, dict):
                continue
            instance_id = str(advisor.get("instance_id") or "")
            if not instance_id:
                continue
            score_policy = get_review_score_threshold_policy(policy.name, instance_id)
            advisor["score_fields"] = list(score_policy.score_fields)
            advisor["score_thresholds_start"] = score_policy.score_thresholds_start
            advisor["score_thresholds"] = score_policy.score_thresholds
            advisor["score_threshold_ramp_cycles"] = score_policy.score_threshold_ramp_cycles

    return policy.name


def _format_threshold_brief(policy: ReviewScoreThresholdPolicy) -> str:
    return ", ".join(
        f"{key}>={value:.2f}"
        for key, value in policy.score_thresholds.items()
    )


def _format_pattern_families(families: tuple[str, ...]) -> str:
    if not families:
        return "(none)"
    labels = {
        "memory_safety": "memory_safety/内存安全",
        "integer_safety": "integer_safety/整数安全",
        "input_validation": "input_validation/输入校验",
        "logic_state": "logic_state/逻辑状态",
        "resource_lifetime": "resource_lifetime/资源生命周期",
        "concurrency_timing": "concurrency_timing/并发时序",
    }
    return ", ".join(labels.get(item, item) for item in families)


def format_review_profile_policy(value: str | None, *, compact: bool = False) -> str:
    policy = get_review_profile_policy(value)
    completeness_thresholds = get_review_score_threshold_policy(policy.name, "global_completeness")
    depth_thresholds = get_review_score_threshold_policy(policy.name, "global_depth")
    required = ", ".join(policy.required_risks) if policy.required_risks else "(none)"
    kinds = ", ".join(policy.required_kinds) if policy.required_kinds else "(none)"
    if compact:
        gate = "on" if policy.enforce_coverage_gate else "off"
        summary_only = "allowed" if policy.allow_summary_only_evidence else "not sufficient"
        return "\n".join([
            "## Review Profile",
            (
                f"- `{policy.name}`: review={'on' if policy.review_enabled else 'off'}; "
                f"gate={gate}; required_risks={required}; "
                f"required_kinds={kinds}; dataflow>={policy.min_declared_extraction_ratio:.0%}; "
                f"summary_only={summary_only}; cycles={policy.default_max_review_cycles}; "
                "worker_internal_turns=unlimited; "
                "reflection_turns=unlimited; "
                "advisor_turns=unlimited; "
                f"min_discovery={policy.min_discovery_cycles_before_pass}; "
                f"progress_after={policy.progress_required_after_cycle}; "
                f"min_evidence_artifacts={policy.min_evidence_artifacts}; "
                f"required_patterns={len(policy.required_pattern_families)}; "
                f"pi_timeout=native; "
                f"depth_threshold={min(depth_thresholds.score_thresholds.values()):.2f}"
            ),
        ])
    return "\n".join([
        "## Review Profile",
        f"- profile: `{policy.name}`",
        f"- 定位: {policy.description}",
        f"- review loop: {'enabled' if policy.review_enabled else 'disabled'}",
        f"- coverage gate: {'enabled' if policy.enforce_coverage_gate else 'disabled'}",
        f"- 必须闭环 risk: {required}",
        f"- 必须闭环 kind: {kinds}",
        f"- data-flow 抽取下限: {policy.min_declared_extraction_ratio:.0%}",
        f"- summary-only evidence: {'allowed' if policy.allow_summary_only_evidence else 'not sufficient'}",
        f"- 默认最大评审轮次: {policy.default_max_review_cycles}",
        "- 单轮 Worker 内部 turn 硬上限: 不限制",
        f"- 单轮 Worker stdout 软上限: {policy.worker_rpc_stdout_abort_bytes // (1024 * 1024)}MB",
        "- 单次 Advisor 内部 turn 硬上限: 不限制",
        f"- 单次 Advisor stdout 软上限: {policy.advisor_rpc_stdout_abort_bytes // (1024 * 1024)}MB",
        f"- 全面性最终分数线: {_format_threshold_brief(completeness_thresholds)}",
        f"- 深入性最终分数线: {_format_threshold_brief(depth_thresholds)}",
        f"- 每轮反思 pass: {policy.reflection_passes_per_cycle}",
        "- 单次反思内部 turn 硬上限: 不限制",
        "- Pi/provider timeout: 仅依赖 Pi 原生 timeout；重发次数/间隔由 runtime_config.timeout_max_retries 与 timeout_retry_interval_seconds 控制",
        f"- 最少探索轮次: {policy.min_discovery_cycles_before_pass}",
        f"- 有效进展检测起始轮: {policy.progress_required_after_cycle or 'disabled'}",
        (
            f"- 无有效进展收敛/终止阈值: "
            f"{policy.progress_no_signal_closure_streak}/"
            f"{policy.progress_no_signal_abort_streak}"
        ),
        f"- 最少证据产物数: {policy.min_evidence_artifacts}",
        f"- 必须覆盖漏洞模式族: {_format_pattern_families(policy.required_pattern_families)}",
        f"- 挖掘目标: {policy.execution_goal}",
        f"- closure 策略: {policy.closure_policy}",
        "- 深挖路线:",
        *[f"  - {lane}" for lane in policy.depth_lanes],
    ])
