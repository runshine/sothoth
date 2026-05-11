from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from app.pi_vuln_core.review.profile import (
    apply_profile_thinking_to_config,
    apply_profile_runtime_policy_to_config,
    get_review_profile_policy,
    get_review_score_threshold_policy,
    normalize_review_profile,
    resolve_profile_thinking,
)

TEMPLATE_FILES = {
    "vuln_scan_default": "config.vuln_scan_default.json",
    "full_pipeline": "config.full_pipeline.json",
}

SERVICE_ROOT = Path(__file__).resolve().parents[2]


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _load_template(template_kind: str) -> dict[str, Any]:
    filename = TEMPLATE_FILES.get(template_kind)
    if not filename:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unsupported template_kind: {template_kind}",
        )
    path = SERVICE_ROOT / filename
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_defaults(template: dict[str, Any]) -> dict[str, Any]:
    agents = template.get("agents") or []
    worker = next((item for item in agents if item.get("id") == "pi-worker"), {})
    advisor = next((item for item in agents if item.get("id") == "pi-advisor"), {})
    worker_runtime = worker.get("runtime_config") or {}
    advisor_runtime = advisor.get("runtime_config") or {}
    return {
        "model": worker_runtime.get("model") or advisor_runtime.get("model") or "",
        "thinking": resolve_profile_thinking(
            worker_runtime.get("model") or advisor_runtime.get("model") or "",
            (
                (((template.get("workflows") or {}).get("atomic") or [{}])[-1].get("engine") or {}).get("review_profile")
                or "balanced"
            ),
        ),
        "max_review_cycles": ((template.get("global") or {}).get("max_review_cycles") or 6),
        "review_profile": (
            (((template.get("workflows") or {}).get("atomic") or [{}])[-1].get("engine") or {}).get("review_profile")
            or "balanced"
        ),
        "agent_run_timeout_seconds": worker_runtime.get("timeout_seconds") or 3600,
        "agent_timeout_retry_enabled": True,
        "agent_timeout_max_retries": (
            max((worker_runtime.get("timeout_max_retries") if worker_runtime.get("timeout_max_retries") is not None else advisor_runtime.get("timeout_max_retries") if advisor_runtime.get("timeout_max_retries") is not None else 3) - 1, 0)
        ),
        "worker_timeout": worker_runtime.get("timeout_seconds") or 3600,
        "advisor_timeout": advisor_runtime.get("timeout_seconds") or 3600,
        "timeout_max_retries": worker_runtime.get("timeout_max_retries") if worker_runtime.get("timeout_max_retries") is not None else advisor_runtime.get("timeout_max_retries") if advisor_runtime.get("timeout_max_retries") is not None else 3,
        "timeout_retry_interval_seconds": worker_runtime.get("timeout_retry_interval_seconds") if worker_runtime.get("timeout_retry_interval_seconds") is not None else advisor_runtime.get("timeout_retry_interval_seconds") if advisor_runtime.get("timeout_retry_interval_seconds") is not None else 30,
        "result_review_concurrency": ((template.get("global") or {}).get("parallel_result_review_limit") or 3),
        "runtime_overrides": {},
    }


def _overrides_engine_max_cycles(overrides: dict[str, Any] | None) -> bool:
    if not isinstance(overrides, dict):
        return False
    workflows = overrides.get("workflows")
    if not isinstance(workflows, dict):
        return False
    atomic_workflows = workflows.get("atomic")
    if not isinstance(atomic_workflows, list):
        return False
    for workflow in atomic_workflows:
        if not isinstance(workflow, dict):
            continue
        engine = workflow.get("engine")
        if isinstance(engine, dict) and "max_review_cycles" in engine:
            return True
    return False


def _first_present_int(*values: Any, default: int) -> int:
    for value in values:
        if value is None or value == "":
            continue
        return int(value)
    return default


def _sync_engine_max_cycles(compiled: dict[str, Any]) -> None:
    global_cycles = (compiled.get("global") or {}).get("max_review_cycles")
    if global_cycles is None:
        return
    for workflow in ((compiled.get("workflows") or {}).get("atomic") or []):
        if not isinstance(workflow, dict):
            continue
        engine = workflow.setdefault("engine", {})
        if "review_profile" in engine or workflow.get("id") == "vuln_scan":
            engine["max_review_cycles"] = int(global_cycles)


def normalize_config_payload(template_kind: str, config_payload: dict[str, Any] | None) -> dict[str, Any]:
    template = _load_template(template_kind)
    defaults = _extract_defaults(template)
    return _deep_merge(defaults, config_payload or {})


class ProfileTemplateService:
    def compile_profile(
        self,
        *,
        template_kind: str,
        config_payload: dict[str, Any] | None,
        runtime_overrides: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        template = _load_template(template_kind)
        normalized_payload = normalize_config_payload(template_kind, config_payload)
        compiled = copy.deepcopy(template)

        model = str(normalized_payload.get("model") or "").strip()
        agent_run_timeout_seconds = int(normalized_payload.get("agent_run_timeout_seconds") if normalized_payload.get("agent_run_timeout_seconds") is not None else 3600)
        agent_timeout_retry_enabled = bool(normalized_payload.get("agent_timeout_retry_enabled") if normalized_payload.get("agent_timeout_retry_enabled") is not None else True)
        agent_timeout_max_retries = max(_first_present_int(normalized_payload.get("agent_timeout_max_retries"), default=3), 0)
        worker_timeout = agent_run_timeout_seconds if agent_run_timeout_seconds > 0 else 3600
        advisor_timeout = agent_run_timeout_seconds if agent_run_timeout_seconds > 0 else 3600
        timeout_max_retries = max(agent_timeout_max_retries + 1, 1) if agent_timeout_retry_enabled else 1
        timeout_retry_interval_seconds = max(_first_present_int(normalized_payload.get("timeout_retry_interval_seconds"), default=30), 0)
        review_profile = normalize_review_profile(normalized_payload.get("review_profile"))
        profile_policy = get_review_profile_policy(review_profile)
        explicit_max_cycles = (
            isinstance(config_payload, dict)
            and "max_review_cycles" in config_payload
        )
        payload_runtime_overrides = normalized_payload.get("runtime_overrides") or {}

        global_cfg = compiled.setdefault("global", {})
        global_cfg["max_review_cycles"] = 1 if not profile_policy.review_enabled else int(
            normalized_payload.get("max_review_cycles")
            if explicit_max_cycles else
            profile_policy.default_max_review_cycles
        )
        global_cfg["parallel_result_review"] = True
        global_cfg["parallel_result_review_limit"] = int(normalized_payload.get("result_review_concurrency") or 3)

        for agent in compiled.get("agents") or []:
            runtime_config = agent.setdefault("runtime_config", {})
            if model:
                runtime_config["model"] = model
            runtime_config["timeout_max_retries"] = timeout_max_retries
            runtime_config["timeout_retry_delay"] = timeout_retry_interval_seconds
            runtime_config["timeout_retry_interval_seconds"] = timeout_retry_interval_seconds
            if agent.get("id") == "pi-worker":
                runtime_config["timeout_seconds"] = worker_timeout
                runtime_config["max_internal_turns"] = 0
                runtime_config["rpc_stdout_trace_bytes"] = profile_policy.worker_rpc_stdout_trace_bytes
                runtime_config["rpc_stdout_abort_bytes"] = profile_policy.worker_rpc_stdout_abort_bytes
            elif agent.get("id") == "pi-advisor":
                runtime_config["timeout_seconds"] = advisor_timeout
                runtime_config["advisor_runtime_retries"] = 0
                runtime_config["max_internal_turns"] = 0
                runtime_config["rpc_stdout_trace_bytes"] = profile_policy.advisor_rpc_stdout_trace_bytes
                runtime_config["rpc_stdout_abort_bytes"] = profile_policy.advisor_rpc_stdout_abort_bytes

        for workflow in ((compiled.get("workflows") or {}).get("atomic") or []):
            engine = workflow.setdefault("engine", {})
            if "review_profile" in engine or workflow.get("id") == "vuln_scan":
                engine["review_profile"] = review_profile
                engine["review_enabled"] = profile_policy.review_enabled
                engine["max_review_cycles"] = global_cfg["max_review_cycles"]
                engine["max_worker_turns_per_cycle"] = profile_policy.max_worker_turns_per_cycle
                engine["reflection_passes_per_cycle"] = profile_policy.reflection_passes_per_cycle
                engine["reflection_max_internal_turns"] = 0
                engine["reflection_rpc_stdout_trace_bytes"] = profile_policy.reflection_rpc_stdout_trace_bytes
                engine["reflection_rpc_stdout_abort_bytes"] = profile_policy.reflection_rpc_stdout_abort_bytes
                engine.setdefault("summary_repair_attempt_budget", 2)
                engine["min_discovery_cycles_before_pass"] = profile_policy.min_discovery_cycles_before_pass
                engine["progress_required_after_cycle"] = profile_policy.progress_required_after_cycle
                engine["progress_no_signal_closure_streak"] = profile_policy.progress_no_signal_closure_streak
                engine["progress_no_signal_abort_streak"] = profile_policy.progress_no_signal_abort_streak
                engine["min_evidence_artifacts"] = profile_policy.min_evidence_artifacts
                engine["required_pattern_families"] = list(profile_policy.required_pattern_families)
                engine["plateau_closure_streak"] = profile_policy.progress_no_signal_closure_streak
                engine["plateau_abort_streak"] = profile_policy.progress_no_signal_abort_streak
                advisors = ((workflow.get("roles") or {}).get("advisors") or {})
                for advisor in advisors.get("global_review") or []:
                    instance_id = str(advisor.get("instance_id") or "")
                    if not instance_id:
                        continue
                    score_policy = get_review_score_threshold_policy(
                        review_profile,
                        instance_id,
                    )
                    advisor["score_fields"] = list(score_policy.score_fields)
                    advisor["score_thresholds_start"] = score_policy.score_thresholds_start
                    advisor["score_thresholds"] = score_policy.score_thresholds
                    advisor["score_threshold_ramp_cycles"] = score_policy.score_threshold_ramp_cycles

        runtime_overrides_set_engine_cycles = (
            _overrides_engine_max_cycles(payload_runtime_overrides)
            or _overrides_engine_max_cycles(runtime_overrides)
        )
        if isinstance(payload_runtime_overrides, dict) and payload_runtime_overrides:
            compiled = _deep_merge(compiled, payload_runtime_overrides)
        if runtime_overrides:
            compiled = _deep_merge(compiled, runtime_overrides)
        if not runtime_overrides_set_engine_cycles:
            _sync_engine_max_cycles(compiled)
        apply_profile_runtime_policy_to_config(compiled, profile_policy.name)
        if not runtime_overrides_set_engine_cycles:
            _sync_engine_max_cycles(compiled)
        apply_profile_thinking_to_config(compiled, profile_policy.name)
        normalized_payload["review_profile"] = profile_policy.name
        normalized_payload["agent_run_timeout_seconds"] = agent_run_timeout_seconds
        normalized_payload["agent_timeout_retry_enabled"] = agent_timeout_retry_enabled
        normalized_payload["agent_timeout_max_retries"] = agent_timeout_max_retries
        normalized_payload["timeout_max_retries"] = timeout_max_retries
        normalized_payload["timeout_retry_interval_seconds"] = timeout_retry_interval_seconds
        normalized_payload["thinking"] = self._extract_resolved_thinking(compiled)
        return normalized_payload, compiled

    def get_supported_templates(self) -> list[str]:
        return sorted(TEMPLATE_FILES.keys())

    @staticmethod
    def _extract_resolved_thinking(compiled: dict[str, Any]) -> str:
        for agent in compiled.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            runtime_config = agent.get("runtime_config")
            if not isinstance(runtime_config, dict):
                continue
            sdk_specific = runtime_config.get("sdk_specific") or {}
            thinking = str(sdk_specific.get("thinking") or "").strip()
            if thinking:
                return thinking
        return ""


_profile_template_service: ProfileTemplateService | None = None


def get_profile_template_service() -> ProfileTemplateService:
    global _profile_template_service
    if _profile_template_service is None:
        _profile_template_service = ProfileTemplateService()
    return _profile_template_service
