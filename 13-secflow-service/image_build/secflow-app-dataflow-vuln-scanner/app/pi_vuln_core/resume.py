from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.composite import WorkflowRegistry
from app.pi_vuln_core.engine.checkpoint import (
    is_terminal_checkpoint,
    load_current_checkpoint,
    load_step_checkpoints,
    node_id_for,
    node_kind_for,
)
from app.pi_vuln_core.engine.models import CompositeWorkflowResult
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.plugins.registry import PluginRegistry
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review_parser import parse_global_review_response
from app.pi_vuln_core.review.profile import (
    apply_profile_runtime_policy_to_config,
    apply_profile_thinking_to_runtime_config,
    get_review_profile_policy,
)
from app.pi_vuln_core.review.state import (
    FailedResultItem,
    GlobalReviewRecord,
    ReviewState,
    calculate_result_fingerprints,
)
from app.pi_vuln_core.runner import RunnerArtifacts, load_framework_config_from_path
from app.pi_vuln_core.utils.file_ops import read_json, write_json
from app.pi_vuln_core.utils.logger import get_logger, setup_logging
from app.pi_vuln_core.utils.result_docs import list_result_report_files
from app.pi_vuln_core.utils.win_compat import safe_rmtree
from app.pi_vuln_core.workspace.manager import WorkspaceManager

logger = get_logger("resume")
_CYCLE_RE = re.compile(r"cycle_(\d+)")
_NODE_RESUME_POLICY = "rerun_current_node"
_WORKER_REWORK_STEP_ORDER = (
    "worker::rework_missed_hunt",
)


@dataclass
class ResumePlan:
    run_dir: str
    config_path: str
    composite_work_dir: str
    atomic_work_dir: str
    stage_id: str
    stage_on_error: str
    task_id: str
    task_file: str
    completed_cycles: int
    worker_session_id: str
    current_status: str
    resume_state: str = ""
    resume_cursor: dict[str, Any] | None = None
    resume_start_cycle: int = 0
    resume_target_phase: str = ""
    resume_target_step_key: str = ""
    node_resume_policy: str = _NODE_RESUME_POLICY
    timeout_detected: bool = False
    timeout_call_dir: str = ""
    timeout_agent_id: str = ""
    timeout_error: str = ""
    timeout_turn_number: int = 0
    checkpoint_cycle: int = 0
    checkpoint_phase: str = ""
    checkpoint_step_key: str = ""
    checkpoint_status: str = ""


def build_resume_plan(run_dir: str | Path) -> tuple[FrameworkConfig, ResumePlan]:
    run_dir = str(Path(run_dir).resolve())
    config_path = str(Path(run_dir) / "run" / "config.json")
    if not os.path.isfile(config_path):
        config_path = str(Path(run_dir) / "config.json")
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"未找到配置文件：{config_path}")

    config = load_framework_config_from_path(config_path)
    wf_registry = WorkflowRegistry(config)
    composite_wf = wf_registry.get_composite(config.execution.entry_workflow)
    stages = sorted(composite_wf.stages, key=lambda s: s.sequence)
    if len(stages) != 1 or stages[0].workflow_type != "atomic":
        raise ValueError("当前 resume 仅支持单阶段 atomic 漏洞扫描流水线")

    stage = stages[0]
    atomic_wf = wf_registry.get_atomic(stage.workflow_ref)
    composite_work_dir = os.path.join(
        config.global_config.workspace_root,
        composite_wf.working_dir_template.format(
            execution_id=config.execution.execution_id,
        ),
    )
    stage_dir = os.path.join(composite_work_dir, stage.stage_id)
    atomic_work_dir = _discover_atomic_work_dir(stage_dir)
    task_id = _extract_task_id_from_dir_name(
        dirname=os.path.basename(atomic_work_dir),
        template=atomic_wf.working_dir_template,
    ) or "initial_001"
    task_file = os.path.join(atomic_work_dir, "input", "task.md")
    if not os.path.isfile(task_file):
        task_file = config.execution.input_task.task_file

    completed_cycles = _load_completed_cycles(atomic_work_dir)
    worker_session_id = _detect_worker_session_id(atomic_work_dir)
    current_status = _load_atomic_status(atomic_work_dir)
    state_detail = _load_atomic_state_detail(atomic_work_dir)
    timeout_info = None if current_status == "completed" else _find_latest_timeout_call(atomic_work_dir)
    checkpoint = None if current_status == "completed" else load_current_checkpoint(atomic_work_dir)
    if checkpoint is None and current_status != "completed":
        historical_checkpoints = load_step_checkpoints(atomic_work_dir)
        checkpoint = historical_checkpoints[-1] if historical_checkpoints else None
    checkpoint_phase = str((checkpoint or {}).get("phase") or "").strip()
    checkpoint_status = str((checkpoint or {}).get("status") or "").strip()
    checkpoint_step_key = str((checkpoint or {}).get("step_key") or "").strip()
    try:
        checkpoint_cycle = int((checkpoint or {}).get("cycle") or 0)
    except (TypeError, ValueError):
        checkpoint_cycle = 0
    resume_cursor = _build_resume_cursor(
        checkpoint=checkpoint,
        completed_cycles=completed_cycles,
        atomic_wf=atomic_wf,
        atomic_work_dir=atomic_work_dir,
    )
    resume_start_cycle = _resume_start_cycle(
        completed_cycles=completed_cycles,
        resume_cursor=resume_cursor,
    )

    resume_state = state_detail.get("current_state", "")
    if resume_cursor:
        resume_state = str(resume_cursor.get("phase") or resume_state)
    elif checkpoint_phase and checkpoint_status != "completed":
        resume_state = checkpoint_phase
    elif timeout_info and state_detail.get("previous_state"):
        # WorkerStageError 会先把 state 切到 failed，真正应恢复的位置保存在 previous_state。
        resume_state = str(state_detail.get("previous_state") or resume_state)

    return config, ResumePlan(
        run_dir=run_dir,
        config_path=config_path,
        composite_work_dir=composite_work_dir,
        atomic_work_dir=atomic_work_dir,
        stage_id=stage.stage_id,
        stage_on_error=stage.on_error,
        task_id=task_id,
        task_file=task_file,
        completed_cycles=completed_cycles,
        worker_session_id=worker_session_id,
        current_status=current_status,
        resume_state=resume_state,
        resume_cursor=resume_cursor,
        resume_start_cycle=resume_start_cycle,
        resume_target_phase=str((resume_cursor or {}).get("phase") or resume_state or ""),
        resume_target_step_key=str((resume_cursor or {}).get("step_key") or ""),
        node_resume_policy=_NODE_RESUME_POLICY,
        timeout_detected=bool(timeout_info),
        timeout_call_dir=str(timeout_info.get("call_dir", "")) if timeout_info else "",
        timeout_agent_id=str(timeout_info.get("agent_id", "")) if timeout_info else "",
        timeout_error=str(timeout_info.get("error", "")) if timeout_info else "",
        timeout_turn_number=int(timeout_info.get("turn_number") or 0) if timeout_info else 0,
        checkpoint_cycle=checkpoint_cycle,
        checkpoint_phase=checkpoint_phase,
        checkpoint_step_key=checkpoint_step_key,
        checkpoint_status=checkpoint_status,
    )


def _resume_start_cycle(
    *,
    completed_cycles: int,
    resume_cursor: dict[str, Any] | None,
) -> int:
    if not resume_cursor:
        return completed_cycles
    try:
        cursor_cycle = int(resume_cursor.get("cycle") or 0)
    except (TypeError, ValueError):
        cursor_cycle = 0
    if cursor_cycle <= completed_cycles:
        return completed_cycles
    return max(completed_cycles, cursor_cycle - 1)


def _build_resume_cursor(
    *,
    checkpoint: dict[str, Any] | None,
    completed_cycles: int,
    atomic_wf,
    atomic_work_dir: str,
) -> dict[str, Any] | None:
    if not isinstance(checkpoint, dict):
        return None
    try:
        cycle = int(checkpoint.get("cycle") or 0)
    except (TypeError, ValueError):
        cycle = 0
    if cycle <= 0 or cycle <= completed_cycles:
        return None

    source_phase = str(checkpoint.get("phase") or "").strip()
    source_step_key = str(checkpoint.get("step_key") or "").strip()
    source_status = str(checkpoint.get("status") or "").strip()
    if not source_phase:
        return None
    if source_phase == "worker":
        source_step_key = _worker_checkpoint_step_key(checkpoint)
    elif not source_step_key:
        source_step_key = source_phase

    if is_terminal_checkpoint(checkpoint):
        target_phase, target_step_key = _next_node_after_checkpoint(
            atomic_wf=atomic_wf,
            atomic_work_dir=atomic_work_dir,
            cycle=cycle,
            source_phase=source_phase,
            source_step_key=source_step_key,
            checkpoint=checkpoint,
        )
    else:
        target_phase, target_step_key = source_phase, source_step_key

    return {
        "cycle": cycle,
        "phase": target_phase,
        "step_key": target_step_key,
        "node_id": node_id_for(cycle=cycle, phase=target_phase, step_key=target_step_key),
        "status": source_status,
        "node_kind": node_kind_for(target_phase, target_step_key),
        "policy": _NODE_RESUME_POLICY,
        "source": {
            "cycle": cycle,
            "phase": source_phase,
            "step_key": source_step_key,
            "node_id": str(checkpoint.get("node_id") or node_id_for(cycle=cycle, phase=source_phase, step_key=source_step_key)),
            "status": source_status,
            "node_kind": str(checkpoint.get("node_kind") or node_kind_for(source_phase, source_step_key)),
            "terminal_status": is_terminal_checkpoint(checkpoint),
        },
    }


def _worker_checkpoint_step_key(checkpoint: dict[str, Any]) -> str:
    step_key = str(checkpoint.get("step_key") or "").strip()
    if step_key in {"worker::work", "worker::rework", "worker::rework_fp_repair", *_WORKER_REWORK_STEP_ORDER}:
        return step_key
    extra = checkpoint.get("extra") if isinstance(checkpoint.get("extra"), dict) else {}
    prompt_kind = str(
        extra.get("prompt_kind")
        or extra.get("worker_prompt_kind")
        or checkpoint.get("prompt_kind")
        or ""
    ).strip().lower()
    return "worker::rework" if prompt_kind == "rework" else "worker::work"


def _next_node_after_checkpoint(
    *,
    atomic_wf,
    atomic_work_dir: str,
    cycle: int,
    source_phase: str,
    source_step_key: str,
    checkpoint: dict[str, Any],
) -> tuple[str, str]:
    if source_phase == "worker":
        source_status = str(checkpoint.get("status") or "").strip()
        if source_step_key in {"worker::rework_triage", "worker::rework_fp_repair"}:
            return "worker", "worker::rework_missed_hunt"
        if source_step_key == "worker::rework_handoff":
            return "summary", "summary"
        if source_step_key in _WORKER_REWORK_STEP_ORDER:
            try:
                index = _WORKER_REWORK_STEP_ORDER.index(source_step_key)
            except ValueError:
                index = -1
            if index >= 0 and index + 1 < len(_WORKER_REWORK_STEP_ORDER):
                return "worker", _WORKER_REWORK_STEP_ORDER[index + 1]
            return "summary", "summary"
        if source_step_key == "worker::rework" or source_status == "partial_salvaged":
            return "summary", "summary"
        first_reflection = _first_reflection_step_key(atomic_wf)
        return ("reflect", first_reflection) if first_reflection else ("summary", "summary")

    if source_phase == "reflect":
        next_reflection = _next_step_key(_reflection_step_keys(atomic_wf), source_step_key)
        return ("reflect", next_reflection) if next_reflection else ("summary", "summary")

    if source_phase == "summary":
        first_global = _first_global_review_step_key(atomic_wf, cycle)
        return ("global_review", first_global) if first_global else ("result_review", _first_result_review_step_key(atomic_wf, atomic_work_dir) or "result::*")

    if source_phase == "global_review":
        next_global = _next_global_review_step_key(
            atomic_wf=atomic_wf,
            atomic_work_dir=atomic_work_dir,
            cycle=cycle,
        )
        if next_global:
            return "global_review", next_global
        return "result_review", _first_result_review_step_key(atomic_wf, atomic_work_dir) or "result::*"

    if source_phase == "result_review":
        next_result = _next_result_review_step_key(
            atomic_wf=atomic_wf,
            atomic_work_dir=atomic_work_dir,
            cycle=cycle,
        )
        return "result_review", next_result or source_step_key or "result::*"

    return source_phase, source_step_key


def _reflection_step_keys(atomic_wf) -> list[str]:
    worker = getattr(getattr(atomic_wf, "roles", None), "worker", None)
    worker_prompts = getattr(worker, "prompts", None)
    prompts = list(getattr(worker_prompts, "reflection", []) or [])
    if not prompts:
        return []
    engine = getattr(atomic_wf, "engine", None)
    configured_passes = getattr(engine, "reflection_passes_per_cycle", None)
    if configured_passes is None:
        policy = get_review_profile_policy(getattr(engine, "review_profile", "balanced"))
        reflection_passes = policy.reflection_passes_per_cycle
    else:
        try:
            reflection_passes = int(configured_passes)
        except (TypeError, ValueError):
            reflection_passes = 0
    if reflection_passes <= 0:
        return []
    return [
        f"reflect::{reflect_cfg.id}::pass_{pass_index:02d}"
        for pass_index in range(1, reflection_passes + 1)
        for reflect_cfg in prompts
    ]


def _first_reflection_step_key(atomic_wf) -> str:
    keys = _reflection_step_keys(atomic_wf)
    return keys[0] if keys else ""


def _global_review_step_keys(atomic_wf, cycle: int) -> list[str]:
    advisors_root = getattr(getattr(atomic_wf, "roles", None), "advisors", None)
    advisors = list(getattr(advisors_root, "global_review", []) or [])
    return [
        f"global::{advisor.instance_id}"
        for advisor in advisors
        if not (cycle > 1 and not advisor.re_review_on_cycle)
    ]


def _first_global_review_step_key(atomic_wf, cycle: int) -> str:
    keys = _global_review_step_keys(atomic_wf, cycle)
    return keys[0] if keys else ""


def _next_global_review_step_key(
    *,
    atomic_wf,
    atomic_work_dir: str,
    cycle: int,
) -> str:
    for key in _global_review_step_keys(atomic_wf, cycle):
        advisor_id = key.split("::", 1)[1]
        if not _global_review_record_valid(
            atomic_work_dir=atomic_work_dir,
            cycle=cycle,
            advisor_id=advisor_id,
        ):
            return key
    return ""


def _first_result_review_step_key(atomic_wf, atomic_work_dir: str) -> str:
    advisors_root = getattr(getattr(atomic_wf, "roles", None), "advisors", None)
    advisors = list(getattr(advisors_root, "result_review", []) or [])
    results_dir = Path(atomic_work_dir) / "results"
    result_files = list_result_report_files(str(results_dir)) if results_dir.is_dir() else []
    if not advisors or not result_files:
        return ""
    return f"result::{result_files[0]}::{advisors[0].instance_id}"


def _next_result_review_step_key(
    *,
    atomic_wf,
    atomic_work_dir: str,
    cycle: int,
) -> str:
    advisors_root = getattr(getattr(atomic_wf, "roles", None), "advisors", None)
    advisors = list(getattr(advisors_root, "result_review", []) or [])
    results_dir = Path(atomic_work_dir) / "results"
    result_files = list_result_report_files(str(results_dir)) if results_dir.is_dir() else []
    if not advisors or not result_files:
        return ""

    for result_file in result_files:
        for advisor in advisors:
            record = _load_valid_result_review_record(
                atomic_work_dir=atomic_work_dir,
                cycle=cycle,
                result_file=result_file,
                advisor_id=advisor.instance_id,
            )
            if record is None:
                return f"result::{result_file}::{advisor.instance_id}"
            if not bool(record.get("passed", False)):
                break
    return ""


def _next_step_key(keys: list[str], current_key: str) -> str:
    if not keys:
        return ""
    if current_key not in keys:
        return keys[0]
    next_index = keys.index(current_key) + 1
    return keys[next_index] if next_index < len(keys) else ""


def _load_valid_result_review_record(
    *,
    atomic_work_dir: str,
    cycle: int,
    result_file: str,
    advisor_id: str,
) -> dict[str, Any] | None:
    path = (
        Path(atomic_work_dir)
        / "reviews"
        / "results"
        / Path(result_file).stem
        / f"cycle_{cycle:03d}"
        / f"{advisor_id}.json"
    )
    if not path.is_file():
        return None
    try:
        data = read_json(path)
    except Exception:
        return None
    if not isinstance(data, dict) or _invalid_review_record(data):
        return None
    return data


def _global_review_record_valid(
    *,
    atomic_work_dir: str,
    cycle: int,
    advisor_id: str,
) -> bool:
    path = (
        Path(atomic_work_dir)
        / "reviews"
        / "global"
        / f"cycle_{cycle:03d}"
        / f"{advisor_id}.json"
    )
    if not path.is_file():
        return False
    try:
        data = read_json(path)
    except Exception:
        return False
    return isinstance(data, dict) and not _invalid_review_record(data)


def _invalid_review_record(data: dict[str, Any]) -> bool:
    parser_mode = str(data.get("parser_mode") or "").strip()
    verdict = str(data.get("verdict") or "").strip()
    return parser_mode == "agent_error" or verdict == "ERROR"


def _normalize_legacy_framework_override_record(data: dict[str, Any]) -> dict[str, Any]:
    if bool(data.get("passed", False)):
        return dict(data)

    raw_response = str(data.get("raw_response") or "")
    if not raw_response.strip():
        return dict(data)

    issues = [
        item for item in list(data.get("issues") or [])
        if isinstance(item, dict)
    ]
    if any(
        str(item.get("actionable_by") or item.get("owner") or "").strip().lower() == "framework"
        for item in issues
    ):
        return dict(data)

    score_keys = [
        str(key).strip()
        for key in (data.get("scores") or {}).keys()
        if str(key).strip()
    ]
    parse_outcome = parse_global_review_response(
        raw_response,
        required_score_keys=score_keys or None,
    )
    if not parse_outcome.schema_valid or not bool(parse_outcome.parsed.passed):
        return dict(data)

    parsed = parse_outcome.parsed
    normalized = dict(data)
    normalized["passed"] = True
    normalized["verdict"] = parsed.verdict or "PASS"
    normalized["feedback"] = parsed.feedback or ""
    normalized["feedback_detail"] = parsed.feedback_detail or parsed.feedback or ""
    normalized["scores"] = dict(parsed.scores or {})
    normalized["confidence"] = parsed.confidence
    normalized["issues"] = list(parsed.issues or [])
    normalized["resolved_issue_ids"] = list(parsed.resolved_issue_ids or [])
    return normalized


def _discover_atomic_work_dir(stage_dir: str | Path) -> str:
    stage_path = Path(stage_dir)
    if not stage_path.is_dir():
        raise FileNotFoundError(f"未找到 stage 目录：{stage_path}")

    candidates = sorted(
        p for p in stage_path.iterdir()
        if p.is_dir() and (p / "_meta").is_dir() and (p / "input" / "task.md").is_file()
    )
    if not candidates:
        raise FileNotFoundError(f"未找到可恢复的 atomic 工作目录：{stage_path}")
    if len(candidates) > 1:
        raise ValueError(
            "检测到多个 atomic 工作目录，当前无法自动判定恢复目标："
            + ", ".join(str(p) for p in candidates)
        )
    return str(candidates[0])


def _extract_task_id_from_dir_name(dirname: str, template: str) -> str:
    marker = "{task_id}"
    if marker not in template:
        return ""
    prefix, suffix = template.split(marker, 1)
    if prefix and not dirname.startswith(prefix):
        return ""
    if suffix and not dirname.endswith(suffix):
        return ""
    start = len(prefix)
    end = len(dirname) - len(suffix) if suffix else len(dirname)
    return dirname[start:end]


def _load_completed_cycles(atomic_work_dir: str | Path) -> int:
    review_dir = Path(atomic_work_dir) / "_meta" / "review_summaries"
    if not review_dir.is_dir():
        return 0
    max_cycle = 0
    for path in review_dir.glob("cycle_*.json"):
        match = _CYCLE_RE.search(path.name)
        if match:
            max_cycle = max(max_cycle, int(match.group(1)))
    return max_cycle


def _load_atomic_status(atomic_work_dir: str | Path) -> str:
    result_path = Path(atomic_work_dir) / "_meta" / "workflow_result.json"
    if not result_path.is_file():
        return ""
    try:
        data = read_json(result_path)
        return str(data.get("status", ""))
    except Exception:
        return ""


def _load_atomic_state_detail(atomic_work_dir: str | Path) -> dict[str, str]:
    state_path = Path(atomic_work_dir) / "_meta" / "state.json"
    if not state_path.is_file():
        return {}
    try:
        data = read_json(state_path)
    except Exception:
        return {}
    return {
        "current_state": str(data.get("current_state") or "").strip(),
        "previous_state": str(data.get("previous_state") or "").strip(),
        "detail": str(data.get("detail") or "").strip(),
    }


def _find_latest_timeout_call(atomic_work_dir: str | Path) -> dict | None:
    """查找最近一次以 timeout 结束的 agent 调用，用于 resume 精确定位。"""
    sessions_root = Path(atomic_work_dir) / "sessions"
    if not sessions_root.is_dir():
        return None

    latest: tuple[float, dict] | None = None
    for response_path in sessions_root.glob("*/calls/*/response.json"):
        try:
            response = read_json(response_path)
        except Exception:
            continue
        status = str(response.get("status") or "").lower().strip()
        error = str(response.get("error") or "")
        if status != "timeout" and "超时" not in error and "timeout" not in error.lower():
            continue

        request_path = response_path.parent / "request.json"
        request = {}
        if request_path.is_file():
            try:
                request = read_json(request_path)
            except Exception:
                request = {}

        payload = {
            "call_dir": str(response_path.parent),
            "session_id": str(request.get("session_id") or response.get("conversation_id") or response_path.parents[2].name),
            "agent_id": str(request.get("agent_id") or ""),
            "turn_number": int(request.get("turn_number") or 0),
            "status": status or "timeout",
            "error": error,
            "request": request,
            "response": response,
        }
        mtime = response_path.stat().st_mtime
        if latest is None or mtime >= latest[0]:
            latest = (mtime, payload)

    return latest[1] if latest else None


def _detect_worker_session_id(atomic_work_dir: str | Path) -> str:
    sessions_root = Path(atomic_work_dir) / "sessions"
    if not sessions_root.is_dir():
        raise FileNotFoundError(f"未找到 sessions 目录：{sessions_root}")

    best_session = ""
    best_call_count = -1

    for session_dir in sorted(p for p in sessions_root.iterdir() if p.is_dir()):
        calls_dir = session_dir / "calls"
        if not calls_dir.is_dir():
            continue

        request_files = sorted(calls_dir.glob("*/request.json"))
        if not request_files:
            continue

        agent_id = ""
        for request_file in request_files:
            try:
                payload = read_json(request_file)
                agent_id = str(payload.get("agent_id", ""))
                if agent_id:
                    break
            except Exception:
                continue

        if agent_id != "pi-worker":
            continue

        call_count = len([p for p in calls_dir.iterdir() if p.is_dir()])
        if call_count > best_call_count:
            best_session = session_dir.name
            best_call_count = call_count

    if not best_session:
        raise FileNotFoundError(f"未找到可恢复的 worker session: {sessions_root}")
    return best_session


def rebuild_review_state(atomic_work_dir: str | Path) -> ReviewState:
    work_dir = str(atomic_work_dir)
    state = ReviewState()

    current_fingerprints = calculate_result_fingerprints(
        os.path.join(work_dir, "results"))

    global_dir = Path(work_dir) / "reviews" / "global"
    if global_dir.is_dir():
        for cycle_dir in sorted(global_dir.glob("cycle_*")):
            cycle = _parse_cycle_from_path(cycle_dir)
            cycle_passed = True
            cycle_scores: dict[str, float] = {}
            cycle_issues: list[dict] = []
            cycle_resolved_issue_ids: list[str] = []
            cycle_feedbacks: list[str] = []

            for review_file in sorted(cycle_dir.glob("*.json")):
                try:
                    data = read_json(review_file)
                except Exception:
                    continue
                if not isinstance(data, dict) or _invalid_review_record(data):
                    continue
                data = _normalize_legacy_framework_override_record(data)
                passed = bool(data.get("passed", False))
                feedback = str(
                    data.get("feedback_detail")
                    or data.get("feedback")
                    or ""
                )
                advisor_id = str(
                    data.get("advisor_instance_id")
                    or review_file.stem
                )
                scores = data.get("scores") or {}
                issues = data.get("issues") or []
                resolved_issue_ids = data.get("resolved_issue_ids") or []
                workflow_mode = str(data.get("workflow_mode") or "").strip()
                state.global_review_history.append(
                    GlobalReviewRecord(
                        cycle=cycle,
                        advisor_id=advisor_id,
                        passed=passed,
                        feedback=feedback,
                        role_name=str(data.get("role_name") or ""),
                        scores=scores,
                        issues=issues,
                    )
                )
                if workflow_mode == "closure":
                    state.activate_closure_mode(cycle, feedback or "resume from closure mode")

                if not cycle_scores:
                    cycle_scores = dict(scores)
                elif scores:
                    merged = dict(cycle_scores)
                    for key, value in scores.items():
                        try:
                            numeric = float(value)
                        except (TypeError, ValueError):
                            numeric = 0.0
                        if key not in merged:
                            merged[key] = numeric
                        else:
                            try:
                                merged[key] = min(float(merged[key]), numeric)
                            except (TypeError, ValueError):
                                merged[key] = numeric
                    cycle_scores = merged

                for item_id in resolved_issue_ids:
                    text = str(item_id).strip()
                    if text and text not in cycle_resolved_issue_ids:
                        cycle_resolved_issue_ids.append(text)

                if not passed:
                    cycle_passed = False
                    if feedback:
                        cycle_feedbacks.append(f"[{advisor_id}] {feedback}")
                    cycle_issues.extend(issues)

            cycle_feedback = "\n\n".join(cycle_feedbacks)
            if cycle_scores or cycle_feedback or cycle_issues or cycle_resolved_issue_ids:
                state.record_global_review_result(
                    cycle=cycle,
                    passed=cycle_passed,
                    feedback=cycle_feedback,
                    scores=cycle_scores,
                    issues=cycle_issues,
                    resolved_issue_ids=cycle_resolved_issue_ids,
                )
                if not cycle_passed:
                    state.record_global_failure(cycle, cycle_feedback)
    results_root = Path(work_dir) / "reviews" / "results"
    if results_root.is_dir():
        for result_dir in sorted(p for p in results_root.iterdir() if p.is_dir()):
            result_file = f"{result_dir.name}.md"
            latest_cycle = -1
            latest_record: dict | None = None
            for cycle_dir in sorted(result_dir.glob("cycle_*")):
                cycle = _parse_cycle_from_path(cycle_dir)
                for review_file in sorted(cycle_dir.glob("*.json")):
                    try:
                        data = read_json(review_file)
                    except Exception:
                        continue
                    if not isinstance(data, dict) or _invalid_review_record(data):
                        continue
                    if cycle >= latest_cycle:
                        latest_cycle = cycle
                        latest_record = data
            if latest_cycle < 0 or latest_record is None:
                continue

            feedback = str(
                latest_record.get("feedback_detail")
                or latest_record.get("feedback")
                or ""
            )
            verdict = str(latest_record.get("verdict") or "").strip().upper()
            confidence = float(latest_record.get("confidence") or 0.0)
            if bool(latest_record.get("passed", False)) or verdict == "CONFIRMED":
                state.mark_result_confirmed(
                    result_file,
                    latest_cycle,
                    current_fingerprints.get(result_file, ""),
                    verdict="CONFIRMED",
                    confidence=confidence,
                    feedback=feedback,
                )
            elif verdict == "FALSE_POSITIVE":
                state.mark_result_false_positive(
                    result_file,
                    latest_cycle,
                    current_fingerprints.get(result_file, ""),
                    verdict="FALSE_POSITIVE",
                    confidence=confidence,
                    feedback=feedback,
                )
            else:
                state.mark_result_pending(
                    result_file,
                    latest_cycle,
                    current_fingerprints.get(result_file, ""),
                    verdict="",
                    confidence=confidence,
                    feedback=feedback,
                )

    _restore_cycle_level_state(work_dir, state)
    return state


def _parse_cycle_from_path(path: str | Path) -> int:
    match = _CYCLE_RE.search(str(path))
    return int(match.group(1)) if match else 0


def _restore_cycle_level_state(work_dir: str, state: ReviewState) -> None:
    """
    从按 cycle 汇总文件中恢复更高层的收敛状态。

    为什么需要它：
    - global review 记录写入时，某些状态（例如该轮结束后切换到 closure）
      可能尚未写进单条 global review 记录；
    - 但 `_meta/review_summaries/` 与 `_meta/cycle_metrics/` 会记录该轮最终模式。
    """
    review_summaries_dir = Path(work_dir) / "_meta" / "review_summaries"
    latest_cycle = -1
    latest_mode = ""
    if review_summaries_dir.is_dir():
        for summary_file in sorted(review_summaries_dir.glob("cycle_*.json")):
            try:
                data = read_json(summary_file)
            except Exception:
                continue
            cycle = int(data.get("cycle") or _parse_cycle_from_path(summary_file))
            if cycle >= latest_cycle:
                latest_cycle = cycle
                latest_mode = str(data.get("workflow_mode") or "").strip()

    plateau_reason = ""
    metrics_dir = Path(work_dir) / "_meta" / "cycle_metrics"
    if metrics_dir.is_dir() and latest_cycle > 0:
        metrics_file = metrics_dir / f"cycle_{latest_cycle:03d}.json"
        if metrics_file.is_file():
            try:
                metrics = read_json(metrics_file)
                plateau_status = metrics.get("plateau_status") or {}
                metrics_mode = str(metrics.get("workflow_mode") or "").strip()
                plateau_mode = str(plateau_status.get("workflow_mode") or "").strip()
                if not latest_mode:
                    latest_mode = plateau_mode or metrics_mode
                elif plateau_mode == "closure":
                    latest_mode = plateau_mode
                plateau_reason = str(
                    plateau_status.get("reason")
                    or ""
                ).strip()
            except Exception:
                pass

    if latest_mode == "closure":
        state.activate_closure_mode(
            latest_cycle if latest_cycle > 0 else 0,
            plateau_reason or "resume from closure mode",
        )


def _normalize_model_name(model: str | None, provider: str | None = None) -> str | None:
    if not model:
        return None
    model = model.strip()
    provider = (provider or "").strip()
    if "/" in model or not provider:
        return model
    return f"{provider}/{model}"


def _apply_runtime_overrides(
    config: FrameworkConfig,
    *,
    model: str | None = None,
    provider: str | None = None,
    thinking: str | None = None,
) -> FrameworkConfig:
    effective_model = _normalize_model_name(model, provider)
    review_profile = "balanced"
    for workflow in getattr(config.workflows, "atomic", []) or []:
        engine = getattr(workflow, "engine", None)
        if engine is not None:
            policy = get_review_profile_policy(getattr(engine, "review_profile", "balanced"))
            engine.review_profile = policy.name
            engine.review_enabled = policy.review_enabled
            review_profile = policy.name
            break
    for agent in config.agents:
        if effective_model:
            agent.runtime_config["model"] = effective_model
        sdk_specific = agent.runtime_config.setdefault("sdk_specific", {})
        # 新版 pi_agent 使用 --model provider/model，不再写入 sdk_specific.provider。
        if "provider" in sdk_specific and effective_model:
            sdk_specific.pop("provider", None)
        apply_profile_thinking_to_runtime_config(agent.runtime_config, review_profile)

    # Old runs may contain stale RPC watchdog / low max_internal_turns values
    # (for example fast profile worker max_internal_turns=35). Re-apply the
    # current profile runtime policy before resuming so historical tasks do not
    # fail again for obsolete framework-side limits.
    payload = config.model_dump(mode="json", by_alias=True)
    apply_profile_runtime_policy_to_config(payload, review_profile)
    return FrameworkConfig.model_validate(payload)


async def resume_run(
    run_dir: str | Path,
    *,
    extra_cycles: int = 5,
    model: str | None = None,
    provider: str | None = None,
    thinking: str | None = None,
    clean_workspace: bool = False,
) -> RunnerArtifacts:
    if extra_cycles < 1:
        raise ValueError("extra_cycles 必须 >= 1")

    config, plan = build_resume_plan(run_dir)
    config = _apply_runtime_overrides(
        config,
        model=model,
        provider=provider,
        thinking=thinking,
    )

    setup_logging(config.global_config.log_level)
    workspace_root = config.global_config.workspace_root
    agent_registry: AgentRuntimeRegistry | None = None
    interrupted = False

    try:
        for key, value in config.global_config.env_vars.items():
            os.environ.setdefault(key, value)

        agent_registry = AgentRuntimeRegistry()
        agent_registry.register_from_config([item.model_dump() for item in config.agents])
        await agent_registry.initialize_all()

        plugin_registry = PluginRegistry()
        plugin_registry.register_from_config([item.model_dump() for item in config.plugins])

        workspace = WorkspaceManager(workspace_root)
        recorder = ExecutionRecorder(workspace_root)
        plugin_executor = PluginChainExecutor(plugin_registry)

        wf_registry = WorkflowRegistry(config)
        composite_wf = wf_registry.get_composite(config.execution.entry_workflow)
        stage = sorted(composite_wf.stages, key=lambda s: s.sequence)[0]
        atomic_wf = wf_registry.get_atomic(stage.workflow_ref)

        engine = AtomicWorkflowEngine(
            wf_def=atomic_wf,
            agent_registry=agent_registry,
            plugin_executor=plugin_executor,
            workspace=workspace,
            recorder=recorder,
            global_config=config.global_config,
        )

        review_state = rebuild_review_state(plan.atomic_work_dir)
        total_cycle_limit = max(plan.completed_cycles, plan.resume_start_cycle) + extra_cycles

        logger.info(
            "resume_run_start",
            run_dir=plan.run_dir,
            atomic_work_dir=plan.atomic_work_dir,
            worker_session_id=plan.worker_session_id,
            completed_cycles=plan.completed_cycles,
            start_cycle=plan.resume_start_cycle,
            total_cycle_limit=total_cycle_limit,
            resume_cursor=plan.resume_cursor or {},
        )

        atomic_result = await engine.resume_from_existing(
            task_file=plan.task_file,
            task_id=plan.task_id,
            work_dir=plan.atomic_work_dir,
            start_cycle=plan.resume_start_cycle,
            total_cycle_limit=total_cycle_limit,
            review_state=review_state,
            worker_session_id=plan.worker_session_id,
            resume_state=plan.resume_state or None,
            resume_cursor=plan.resume_cursor,
        )

        composite_result = await _write_composite_result(
            recorder=recorder,
            plan=plan,
            atomic_result=atomic_result,
        )

        summary_file = (
            config.execution.on_completion.summary_file
            if config.execution.on_completion.write_summary else None
        )
        if summary_file:
            write_json(summary_file, composite_result.to_dict())

        logger.info(
            "resume_run_done",
            status=composite_result.status,
            error=composite_result.error,
            summary_file=summary_file,
        )

        return RunnerArtifacts(
            config=config,
            result=composite_result,
            summary_file=summary_file,
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        interrupted = True
        raise
    finally:
        if agent_registry:
            try:
                await agent_registry.shutdown_all()
            except Exception:
                logger.warning("agent_registry_shutdown_failed", exc_info=True)
        if clean_workspace and not interrupted and workspace_root and os.path.isdir(workspace_root):
            safe_rmtree(workspace_root, ignore_errors=True)


async def _write_composite_result(
    *,
    recorder: ExecutionRecorder,
    plan: ResumePlan,
    atomic_result,
) -> CompositeWorkflowResult:
    composite_meta_dir = Path(plan.composite_work_dir) / "_meta"
    composite_meta_dir.mkdir(parents=True, exist_ok=True)

    abnormal_exit_path = composite_meta_dir / "abnormal_exit.json"
    workflow_result_path = composite_meta_dir / "workflow_result.json"

    if atomic_result.success:
        if abnormal_exit_path.exists():
            abnormal_exit_path.unlink()

        composite_result = CompositeWorkflowResult(
            status="completed",
            final_tasks=atomic_result.next_tasks,
            working_dir=plan.composite_work_dir,
            completed_stages=[plan.stage_id],
            total_stages=1,
            total_tasks_processed=1,
        )
        write_json(workflow_result_path, composite_result.to_dict())
        return composite_result

    await recorder.record_abnormal_exit(
        plan.composite_work_dir,
        f"Stage {plan.stage_id} {plan.stage_on_error}: {plan.task_id}: {atomic_result.error or '未知错误'}",
    )
    composite_result = CompositeWorkflowResult(
        status="failed",
        error=f"Stage {plan.stage_id} 失败， 策略={plan.stage_on_error}",
        working_dir=plan.composite_work_dir,
        completed_stages=[],
        total_stages=1,
        total_tasks_processed=1,
    )
    if workflow_result_path.exists():
        workflow_result_path.unlink()
    return composite_result
