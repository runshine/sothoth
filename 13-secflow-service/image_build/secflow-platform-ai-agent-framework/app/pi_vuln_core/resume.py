from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.composite import WorkflowRegistry
from app.pi_vuln_core.engine.models import CompositeWorkflowResult
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.plugins.registry import PluginRegistry
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.state import (
    FailedResultItem,
    GlobalReviewRecord,
    ReviewState,
    calculate_result_fingerprints,
)
from app.pi_vuln_core.runner import RunnerArtifacts, load_framework_config_from_path
from app.pi_vuln_core.utils.file_ops import read_json, write_json
from app.pi_vuln_core.utils.logger import get_logger, setup_logging
from app.pi_vuln_core.workspace.manager import WorkspaceManager

logger = get_logger("resume")
_CYCLE_RE = re.compile(r"cycle_(\d+)")


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


def build_resume_plan(run_dir: str | Path) -> tuple[FrameworkConfig, ResumePlan]:
    run_dir = str(Path(run_dir).resolve())
    config_path = str(Path(run_dir) / "config.json")
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"未找到配置文件: {config_path}")

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
    )


def _discover_atomic_work_dir(stage_dir: str | Path) -> str:
    stage_path = Path(stage_dir)
    if not stage_path.is_dir():
        raise FileNotFoundError(f"未找到 stage 目录: {stage_path}")

    candidates = sorted(
        p for p in stage_path.iterdir()
        if p.is_dir() and (p / "_meta").is_dir() and (p / "input" / "task.md").is_file()
    )
    if not candidates:
        raise FileNotFoundError(f"未找到可恢复的 atomic 工作目录: {stage_path}")
    if len(candidates) > 1:
        raise ValueError(
            "检测到多个 atomic 工作目录，当前无法自动判定恢复目标: "
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


def _detect_worker_session_id(atomic_work_dir: str | Path) -> str:
    sessions_root = Path(atomic_work_dir) / "sessions"
    if not sessions_root.is_dir():
        raise FileNotFoundError(f"未找到 sessions 目录: {sessions_root}")

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
            for review_file in sorted(cycle_dir.glob("*.json")):
                try:
                    data = read_json(review_file)
                except Exception:
                    continue
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
                blocking_issues = data.get("blocking_issues") or []
                resolved_issue_ids = data.get("resolved_issue_ids") or []
                workflow_mode = str(data.get("workflow_mode") or "").strip()
                state.global_review_history.append(
                    GlobalReviewRecord(
                        cycle=cycle,
                        advisor_id=advisor_id,
                        passed=passed,
                        feedback=feedback,
                    )
                )
                if workflow_mode == "closure":
                    state.activate_closure_mode(cycle, feedback or "resume from closure mode")
                state.record_global_review_result(
                    cycle=cycle,
                    passed=passed,
                    feedback=feedback,
                    scores=scores,
                    blocking_issues=blocking_issues,
                    resolved_issue_ids=resolved_issue_ids,
                )
                if not passed:
                    state.record_global_failure(cycle, feedback)

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
            if bool(latest_record.get("passed", False)):
                state.mark_result_passed(
                    result_file,
                    latest_cycle,
                    current_fingerprints.get(result_file, ""),
                )
            else:
                state.record_result_failures(
                    [FailedResultItem(filename=result_file, reason=feedback)],
                    latest_cycle,
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


def _apply_runtime_overrides(
    config: FrameworkConfig,
    *,
    model: str | None = None,
    provider: str | None = None,
    thinking: str | None = None,
) -> None:
    for agent in config.agents:
        if model:
            agent.runtime_config["model"] = model
        sdk_specific = agent.runtime_config.setdefault("sdk_specific", {})
        if provider:
            sdk_specific["provider"] = provider
        if thinking:
            sdk_specific["thinking"] = thinking


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
    _apply_runtime_overrides(
        config,
        model=model,
        provider=provider,
        thinking=thinking,
    )

    setup_logging(config.global_config.log_level)
    workspace_root = config.global_config.workspace_root
    agent_registry: AgentRuntimeRegistry | None = None

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
        total_cycle_limit = plan.completed_cycles + extra_cycles

        logger.info(
            "resume_run_start",
            run_dir=plan.run_dir,
            atomic_work_dir=plan.atomic_work_dir,
            worker_session_id=plan.worker_session_id,
            completed_cycles=plan.completed_cycles,
            total_cycle_limit=total_cycle_limit,
        )

        atomic_result = await engine.resume_from_existing(
            task_file=plan.task_file,
            task_id=plan.task_id,
            work_dir=plan.atomic_work_dir,
            start_cycle=plan.completed_cycles,
            total_cycle_limit=total_cycle_limit,
            review_state=review_state,
            worker_session_id=plan.worker_session_id,
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
    finally:
        if agent_registry:
            try:
                await agent_registry.shutdown_all()
            except Exception:
                logger.warning("agent_registry_shutdown_failed", exc_info=True)
        if clean_workspace and workspace_root and os.path.isdir(workspace_root):
            shutil.rmtree(workspace_root, ignore_errors=True)


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
        error=f"Stage {plan.stage_id} 失败, 策略={plan.stage_on_error}",
        working_dir=plan.composite_work_dir,
        completed_stages=[],
        total_stages=1,
        total_tasks_processed=1,
    )
    if workflow_result_path.exists():
        workflow_result_path.unlink()
    return composite_result
