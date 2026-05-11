"""
原子工作流引擎

完整生命周期：
启动插件 → Worker → 反思 → 总结 → 全局评审 → 结果评审 → (循环) → 结束插件
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef, GlobalConfig
from app.pi_vuln_core.engine.models import (
    AtomicWorkflowState, AtomicWorkflowResult,
    WorkflowContext, TaskItem,
)
from app.pi_vuln_core.engine.worker import WorkerExecutor, WorkerStageError
from app.pi_vuln_core.plugins.base import PluginContext
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.profile import get_review_profile_policy
from app.pi_vuln_core.review.result_review import ResultReviewFrameworkError
from app.pi_vuln_core.review.scheduler import ReviewScheduler
from app.pi_vuln_core.review.state import (
    GlobalReviewRecord,
    ReviewState,
    calculate_result_fingerprints,
)
from app.pi_vuln_core.workspace.manager import WorkspaceManager
from app.pi_vuln_core.utils.file_ops import read_json, copy_file, list_dir_files, write_json
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.result_docs import (
    collect_multi_finding_result_reports,
    list_result_report_files,
)
from app.pi_vuln_core.utils.visual_log import vlog

logger = get_logger("atomic_engine")


class AtomicWorkflowEngine:
    """原子工作流引擎 (R4, R6)"""

    def __init__(
        self,
        wf_def: AtomicWorkflowDef,
        agent_registry: AgentRuntimeRegistry,
        plugin_executor: PluginChainExecutor,
        workspace: WorkspaceManager,
        recorder: ExecutionRecorder,
        global_config: GlobalConfig,
    ):
        self.wf = wf_def
        self.agents = agent_registry
        self.plugin_exec = plugin_executor
        self.workspace = workspace
        self.recorder = recorder
        self.global_cfg = global_config

        self.worker_exec = WorkerExecutor(agent_registry, recorder)
        self.review_sched = ReviewScheduler(agent_registry, recorder)

        self.max_cycles = (
            wf_def.engine.max_review_cycles
            if wf_def.engine.max_review_cycles is not None
            else global_config.max_review_cycles
        )

    @staticmethod
    def _load_recorded_state(work_dir: str) -> str:
        state_path = Path(work_dir) / "_meta" / "state.json"
        if not state_path.is_file():
            return AtomicWorkflowState.CREATED.value
        try:
            payload = read_json(state_path)
        except Exception:
            return AtomicWorkflowState.CREATED.value
        current_state = str(payload.get("current_state") or "").strip()
        return current_state or AtomicWorkflowState.CREATED.value

    async def _transition_state(
        self,
        ctx: WorkflowContext,
        new_state: AtomicWorkflowState,
        detail: str = "",
    ) -> None:
        await self.recorder.record_state_change(
            work_dir=ctx.working_dir,
            old_state=ctx.current_state,
            new_state=new_state.value,
            detail=detail,
        )
        ctx.current_state = new_state.value

    async def run(
        self, task_file: str, task_id: str,
        parent_dir: Optional[str] = None,
    ) -> AtomicWorkflowResult:
        work_dir = self.workspace.create_atomic_dir(
            self.wf.working_dir_template, task_id=task_id,
            parent_dir=parent_dir)

        input_task = os.path.join(work_dir, "input", "task.md")
        copy_file(task_file, input_task)

        vlog.workflow_start(self.wf.id, task_id, work_dir)
        logger.info("atomic_workflow_start",
                     workflow_id=self.wf.id, task_id=task_id,
                     work_dir=work_dir)

        result = await self._execute_once(work_dir, input_task, task_id)
        if result.action == "restart_workflow":
            logger.error(
                "workflow_restart_blocked",
                workflow_id=self.wf.id,
                reason="automatic workflow restart is disabled",
            )
            result.status = "failed"
            result.error = result.error or "自动重启整个工作流已禁用"

        await self.recorder.record_workflow_result(
            work_dir=work_dir, status=result.status,
            detail={"cycles_used": result.cycles_used, "error": result.error})

        if result.success:
            vlog.workflow_completed(result.cycles_used, len(result.next_tasks))
        else:
            vlog.workflow_failed(result.error or "unknown")

        logger.info("atomic_workflow_done",
                     workflow_id=self.wf.id, status=result.status,
                     cycles=result.cycles_used,
                     next_tasks=len(result.next_tasks))
        return result

    async def resume_from_existing(
        self,
        *,
        task_file: str,
        task_id: str,
        work_dir: str,
        start_cycle: int,
        total_cycle_limit: int,
        review_state: ReviewState,
        worker_session_id: str | None = None,
        advisor_sessions: dict[str, str] | None = None,
        resume_state: str | None = None,
    ) -> AtomicWorkflowResult:
        if total_cycle_limit <= start_cycle:
            raise ValueError(
                f"total_cycle_limit ({total_cycle_limit}) 必须大于 start_cycle ({start_cycle})")

        ctx = WorkflowContext(
            workflow_id=self.wf.id,
            task_id=task_id,
            task_file=task_file,
            working_dir=work_dir,
            cycle=start_cycle,
            current_state=resume_state or self._load_recorded_state(work_dir),
            worker_session_id=worker_session_id,
            advisor_sessions=advisor_sessions or {},
            summary_file=(os.path.join(work_dir, "summary.md")
                          if os.path.isfile(os.path.join(work_dir, "summary.md")) else None),
            results_dir=(os.path.join(work_dir, "results")
                         if os.path.isdir(os.path.join(work_dir, "results")) else None),
            review_mode=review_state.workflow_mode,
            review_profile=self.wf.engine.review_profile,
        )

        vlog.workflow_start(f"{self.wf.id}:resume", task_id, work_dir)
        logger.info(
            "atomic_workflow_resume_start",
            workflow_id=self.wf.id,
            task_id=task_id,
            work_dir=work_dir,
            start_cycle=start_cycle,
            total_cycle_limit=total_cycle_limit,
            worker_session_id=worker_session_id,
            resume_state=resume_state or "",
        )

        try:
            cycle_result = await self._run_review_cycles(
                ctx,
                review_state,
                start_cycle=start_cycle,
                total_cycle_limit=total_cycle_limit,
                resume_from_state=resume_state,
            )
            if cycle_result is not None:
                result = cycle_result
            else:
                result = await self._run_end_and_collect(ctx)
                result.cycles_used = ctx.cycle

            await self.recorder.record_workflow_result(
                work_dir=work_dir,
                status=result.status,
                detail={"cycles_used": result.cycles_used, "error": result.error},
            )

            if result.success:
                vlog.workflow_completed(result.cycles_used, len(result.next_tasks))
            else:
                vlog.workflow_failed(result.error or "unknown")

            logger.info(
                "atomic_workflow_resume_done",
                workflow_id=self.wf.id,
                status=result.status,
                cycles=result.cycles_used,
                next_tasks=len(result.next_tasks),
            )
            return result
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            await self._record_interrupt_abnormal_exit(
                work_dir=work_dir,
                task_id=task_id,
                cycle=ctx.cycle,
                review_mode=ctx.review_mode,
                exc=exc,
                worker_session_id=ctx.worker_session_id,
                summary_file=ctx.summary_file,
                results_dir=ctx.results_dir,
            )
            raise

    async def _record_interrupt_abnormal_exit(
        self,
        *,
        work_dir: str,
        task_id: str,
        cycle: int,
        review_mode: str,
        exc: BaseException,
        worker_session_id: str | None = None,
        summary_file: str | None = None,
        results_dir: str | None = None,
    ) -> None:
        error = f"Atomic workflow interrupted (SIGINT / KeyboardInterrupt): {self.wf.id}/{task_id}"
        context = {
            "exception_type": type(exc).__name__,
            "workflow_id": self.wf.id,
            "task_id": task_id,
            "cycle": cycle,
            "review_mode": review_mode,
            "worker_session_id": worker_session_id or "",
            "summary_file": summary_file or "",
            "results_dir": results_dir or "",
        }
        await self.recorder.record_abnormal_exit(work_dir, error, context)
        logger.warning(
            "atomic_workflow_interrupted",
            workflow_id=self.wf.id,
            task_id=task_id,
            work_dir=work_dir,
            cycle=cycle,
            exception_type=type(exc).__name__,
        )

    async def _execute_once(
        self, work_dir: str, task_file: str, task_id: str,
    ) -> AtomicWorkflowResult:

        ctx = WorkflowContext(
            workflow_id=self.wf.id,
            task_id=task_id,
            task_file=task_file,
            working_dir=work_dir,
            current_state=self._load_recorded_state(work_dir),
            review_profile=self.wf.engine.review_profile,
        )

        try:
            # ═══ 阶段1: 启动插件 ═══
            vlog.section("🔌", "启动插件链", f"{len(self.wf.start_plugins)} 个插件")
            await self._transition_state(ctx, AtomicWorkflowState.START_PLUGINS)

            start_result = await self._run_plugins(self.wf.start_plugins, ctx, "start")
            if start_result.action == "restart_workflow":
                return AtomicWorkflowResult(
                    status="failed", action="restart_workflow", working_dir=work_dir)
            if start_result.action == "exit_workflow":
                return AtomicWorkflowResult(
                    status="failed", error=start_result.error, working_dir=work_dir)
            if start_result.action == "end_stage_skip_next":
                return await self._run_end_and_collect(ctx)

            # ═══ 阶段2-6: Worker + Review 循环 ═══
            review_state = ReviewState()
            cycle_result = await self._run_review_cycles(
                ctx,
                review_state,
                start_cycle=0,
                total_cycle_limit=self.max_cycles,
            )
            if cycle_result is not None:
                return cycle_result

            result = await self._run_end_and_collect(ctx)
            result.cycles_used = ctx.cycle
            return result
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            await self._record_interrupt_abnormal_exit(
                work_dir=work_dir,
                task_id=task_id,
                cycle=ctx.cycle,
                review_mode=ctx.review_mode,
                exc=exc,
                worker_session_id=ctx.worker_session_id,
                summary_file=ctx.summary_file,
                results_dir=ctx.results_dir,
            )
            raise

    async def _fail_worker_stage(
        self,
        *,
        ctx: WorkflowContext,
        phase: str,
        message: str,
    ) -> AtomicWorkflowResult:
        error = f"Worker {phase} 阶段失败：{message}"
        await self.recorder.record_warning(ctx.working_dir, error)
        await self._transition_state(ctx, AtomicWorkflowState.FAILED, detail=error)
        logger.error(
            "worker_stage_failed",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            phase=phase,
            error=message,
        )
        return AtomicWorkflowResult(
            status=self._classify_terminal_status(message, default="failed"),
            error=error,
            working_dir=ctx.working_dir,
            cycles_used=ctx.cycle,
        )

    @staticmethod
    def _classify_terminal_status(message: str, *, default: str = "failed") -> str:
        lower = (message or "").lower()
        if "summary_incomplete" in lower:
            return "summary_incomplete"
        if "runtime_output_limit" in lower or "stdout limit" in lower or "output limit" in lower:
            return "runtime_output_limit"
        if "runtime_timeout" in lower or "no-progress timeout" in lower or "max wall clock" in lower or "timed out" in lower:
            return "runtime_timeout"
        if "contextwindowexceeded" in lower or "context window" in lower or "context length" in lower:
            return "blocked_context_window"
        if "quota" in lower or "insufficient_quota" in lower or "billing" in lower:
            return "blocked_quota"
        if "rate limit" in lower or "429" in lower:
            return "provider_rate_limited"
        if "schema" in lower and "json" in lower:
            return "model_contract_violation"
        return default

    def _apply_profile_min_discovery_gate(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        cycle: int,
        global_passed: bool,
        global_feedback: str,
        result_passed: bool,
    ) -> tuple[bool, str]:
        if not global_passed or not result_passed:
            return global_passed, global_feedback

        policy = get_review_profile_policy(ctx.review_profile)
        configured = getattr(self.wf.engine, "min_discovery_cycles_before_pass", None)
        min_cycles = int(configured) if configured is not None else policy.min_discovery_cycles_before_pass
        if cycle >= min_cycles:
            return global_passed, global_feedback

        remaining = min_cycles - cycle
        issue = {
            "id": f"profile-{policy.name}-min-discovery-cycle-{cycle + 1}",
            "category": "profile_depth_budget",
            "target": f"cycle_{cycle + 1:03d}",
            "severity": "medium" if policy.name in {"fast", "balanced"} else "high",
            "required_action": (
                f"当前 review_profile={policy.name} 至少需要 {min_cycles} 个探索轮次；"
                f"下一轮必须按本档目标继续深挖：{policy.execution_goal}"
            ),
            "detail": (
                f"本轮全局评审和结果评审已通过，但 profile execution policy "
                f"要求继续执行 {remaining} 个探索轮次，避免高档位过早停在低档结果。"
            ),
            "owner": "worker",
            "actionable_by": "worker",
            "blocking_type": "profile_depth_budget",
            "acceptance_criteria": (
                f"完成至少 {min_cycles} 个探索轮次；若没有新增漏洞，"
                "supporting_docs 中必须记录本轮补扫范围、负面证据和未形成漏洞原因。"
            ),
        }
        feedback = (
            f"[profile_min_discovery_cycles] review_profile={policy.name} "
            f"要求至少 {min_cycles} 个探索轮次；当前 Cycle {cycle} 已通过，"
            f"但还需继续 {remaining} 轮以执行更高档深挖目标：{policy.execution_goal}"
        )
        review_state.record_global_review_result(
            cycle=cycle,
            passed=False,
            feedback=feedback,
            scores=dict(review_state.last_global_scores or {}),
            issues=[issue],
            resolved_issue_ids=[],
        )
        review_state.global_review_history.append(
            GlobalReviewRecord(
                cycle=cycle,
                advisor_id="profile_execution_policy",
                role_name="Review Profile Execution Policy",
                passed=False,
                feedback=feedback,
                scores=dict(review_state.last_global_scores or {}),
                issues=[issue],
            )
        )
        ctx.plateau_reason = "profile_min_discovery_cycles"
        logger.info(
            "profile_min_discovery_gate",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            review_profile=policy.name,
            cycle=cycle,
            min_discovery_cycles=min_cycles,
        )
        return False, feedback

    async def _run_review_cycles(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
        *,
        start_cycle: int,
        total_cycle_limit: int,
        resume_from_state: str | None = None,
    ) -> AtomicWorkflowResult | None:
        work_dir = ctx.working_dir
        cycle_metrics_history: list[dict] = []
        review_state.workflow_mode = ctx.review_mode
        profile_policy = get_review_profile_policy(ctx.review_profile)
        ctx.review_profile = profile_policy.name
        review_enabled = bool(getattr(self.wf.engine, "review_enabled", profile_policy.review_enabled)) and profile_policy.review_enabled
        if not review_enabled:
            total_cycle_limit = min(total_cycle_limit, 1)
        if review_state.global_review_history and not review_state.issue_ledger:
            review_state.rebuild_issue_ledger_from_history()

        phase_order = {
            AtomicWorkflowState.WORKER.value: 0,
            AtomicWorkflowState.REFLECT.value: 1,
            AtomicWorkflowState.SUMMARY.value: 2,
            AtomicWorkflowState.GLOBAL_REVIEW.value: 3,
            AtomicWorkflowState.RESULT_REVIEW.value: 4,
        }
        normalized_resume_state = (resume_from_state or "").strip()
        if normalized_resume_state not in phase_order:
            normalized_resume_state = AtomicWorkflowState.WORKER.value

        for cycle in range(start_cycle + 1, total_cycle_limit + 1):
            ctx.cycle = cycle
            review_state.workflow_mode = ctx.review_mode
            vlog.cycle_start(cycle, total_cycle_limit)

            cycle_resume_state = (
                normalized_resume_state
                if cycle == start_cycle + 1 else AtomicWorkflowState.WORKER.value
            )
            resume_index = phase_order.get(cycle_resume_state, 0)
            skip_worker = resume_index > phase_order[AtomicWorkflowState.WORKER.value]
            skip_reflect = resume_index > phase_order[AtomicWorkflowState.REFLECT.value]
            skip_summary = resume_index > phase_order[AtomicWorkflowState.SUMMARY.value]
            skip_global_review = resume_index > phase_order[AtomicWorkflowState.GLOBAL_REVIEW.value]
            summary_repair_cycle = bool(ctx.pending_summary_repair and not skip_summary)
            worker_partial_salvaged = False
            worker_rework_skip_reflection = False
            if summary_repair_cycle:
                ctx.summary_repair_attempts += 1
                ctx.pending_summary_repair = False
                ctx.review_mode = "closure"
                review_state.workflow_mode = "closure"
                skip_worker = True
                skip_reflect = True
                logger.info(
                    "summary_repair_cycle_start",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=cycle,
                    attempt=ctx.summary_repair_attempts,
                )

            # ── 2. Worker 执行 ──
            if not skip_worker:
                vlog.worker_start(cycle)
                await self._transition_state(
                    ctx,
                    AtomicWorkflowState.WORKER,
                    detail=f"cycle={cycle},mode={ctx.review_mode}",
                )
                try:
                    worker_response = await self.worker_exec.execute_worker(self.wf, ctx, review_state)
                except WorkerStageError as exc:
                    return await self._fail_worker_stage(
                        ctx=ctx,
                        phase=exc.phase,
                        message=str(exc),
                    )
                worker_partial_salvaged = bool(
                    (worker_response.metadata or {}).get("partial_salvaged")
                )
                worker_rework_skip_reflection = bool(
                    (worker_response.metadata or {}).get("skip_reflection_after_worker")
                )
                vlog.worker_done(worker_response.turn_count)
            elif summary_repair_cycle:
                logger.info(
                    "summary_repair_skip_worker",
                    cycle=cycle,
                    reason="summary_or_ledger repair uses summary stage only",
                )
            else:
                logger.info("resume_skip_worker", cycle=cycle, resume_state=cycle_resume_state)

            if worker_partial_salvaged:
                skip_reflect = True
            elif worker_rework_skip_reflection:
                skip_reflect = True

            # ── 3. 自我反思 ──
            if not skip_reflect:
                await self._transition_state(ctx, AtomicWorkflowState.REFLECT)
                for i, r in enumerate(self.wf.roles.worker.prompts.reflection):
                    vlog.reflection_start(i + 1, r.id)
                try:
                    await self.worker_exec.execute_reflection(self.wf, ctx, review_state)
                except WorkerStageError as exc:
                    return await self._fail_worker_stage(
                        ctx=ctx,
                        phase=exc.phase,
                        message=str(exc),
                    )
                if self.wf.roles.worker.prompts.reflection:
                    vlog.reflection_done(len(self.wf.roles.worker.prompts.reflection))
            elif summary_repair_cycle:
                logger.info(
                    "summary_repair_skip_reflection",
                    cycle=cycle,
                    reason="summary_or_ledger repair does not need discovery reflection",
                )
            elif worker_partial_salvaged:
                logger.info(
                    "worker_partial_salvage_skip_reflection",
                    cycle=cycle,
                    reason="worker hit runtime turn limit after producing artifacts; proceed to summary/review",
                )
            elif worker_rework_skip_reflection:
                logger.info(
                    "worker_rework_skip_reflection",
                    cycle=cycle,
                    reason="rework cycles use worker/rework + summary without reflection",
                )
            else:
                logger.info("resume_skip_reflection", cycle=cycle, resume_state=cycle_resume_state)

            # ── 4. 总结 ──
            if not skip_summary:
                await self._transition_state(ctx, AtomicWorkflowState.SUMMARY)
                try:
                    summary_path, results_dir = await self.worker_exec.execute_summary(
                        self.wf,
                        ctx,
                        review_state,
                    )
                except WorkerStageError as exc:
                    return await self._fail_worker_stage(
                        ctx=ctx,
                        phase=exc.phase,
                        message=str(exc),
                    )
                # fast 档不进入评审兜底，必须由 Worker 真实生成非空 summary.md。
                if not os.path.isfile(summary_path) or (
                    not review_enabled and os.path.getsize(summary_path) <= 0
                ):
                    if not review_enabled:
                        return await self._fail_worker_stage(
                            ctx=ctx,
                            phase="summary",
                            message=(
                                "summary_incomplete: fast profile requires Worker "
                                "to generate a non-empty summary.md before completion"
                            ),
                        )
                    logger.warning(
                        "summary_not_found",
                        summary_path=summary_path,
                        msg="Worker 未生成 summary.md，创建占位文件",
                    )
                    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
                    with open(summary_path, "w", encoding="utf-8") as f:
                        f.write("# Summary\n\nWorker 未在本轮生成分析报告。\n")
                ctx.summary_file = summary_path
                ctx.results_dir = results_dir
                result_files = list_result_report_files(results_dir)
                vlog.summary_done(summary_path, len(result_files))
                await self.recorder.snapshot_summary(work_dir, cycle)

                # ── 4.5 结果粒度预检 ──
                await self._precheck_result_granularity(ctx, review_state)
            else:
                ctx.summary_file = ctx.summary_file or os.path.join(work_dir, "summary.md")
                ctx.results_dir = ctx.results_dir or os.path.join(work_dir, "results")
                result_files = list_result_report_files(ctx.results_dir)
                logger.info(
                    "resume_skip_summary",
                    cycle=cycle,
                    resume_state=cycle_resume_state,
                    summary_file=ctx.summary_file,
                    results_dir=ctx.results_dir,
                )

            if not review_enabled:
                if (
                    not ctx.summary_file
                    or not os.path.isfile(ctx.summary_file)
                    or os.path.getsize(ctx.summary_file) <= 0
                ):
                    return await self._fail_worker_stage(
                        ctx=ctx,
                        phase="summary",
                        message=(
                            "summary_incomplete: fast profile requires Worker "
                            "to generate a non-empty summary.md before completion"
                        ),
                    )
                await self.recorder.record_review_cycle_summary(
                    work_dir=work_dir,
                    cycle=cycle,
                    global_passed=True,
                    global_feedback="review disabled by fast profile",
                    total_results=len(result_files),
                    passed_results=[],
                    failed_results=[],
                    workflow_mode=ctx.review_mode,
                    issues=[],
                    plateau_status={
                        "workflow_mode": ctx.review_mode,
                        "review_enabled": False,
                    },
                    global_advisor_results=[],
                )
                logger.info(
                    "profile_review_disabled_completed_after_summary",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=cycle,
                    review_profile=profile_policy.name,
                    summary_file=ctx.summary_file,
                    result_count=len(result_files),
                )
                return None

            # ── 5. 全局评审 ──
            global_advisors = self.wf.roles.advisors.global_review
            vlog.global_review_start(cycle, len(global_advisors))
            if not skip_global_review:
                await self._transition_state(ctx, AtomicWorkflowState.GLOBAL_REVIEW)

                global_passed, global_feedback = await self.review_sched.run_global_review(
                    advisors_def=self.wf.roles.advisors,
                    task_file=ctx.task_file,
                    summary_file=ctx.summary_file,
                    results_dir=ctx.results_dir,
                    work_dir=work_dir,
                    cycle=cycle,
                    review_state=review_state,
                    advisor_sessions=ctx.advisor_sessions,
                    engine_config=self.wf.engine,
                )
            else:
                existing_global_records = review_state.get_global_review_records(cycle)
                if existing_global_records:
                    global_passed = all(item.passed for item in existing_global_records)
                    failed_record = next((item for item in existing_global_records if not item.passed), None)
                    global_feedback = (failed_record.feedback if failed_record else "") or ""
                else:
                    logger.warning(
                        "resume_skip_global_without_records_rerun",
                        cycle=cycle,
                        resume_state=cycle_resume_state,
                    )
                    await self._transition_state(ctx, AtomicWorkflowState.GLOBAL_REVIEW)
                    global_passed, global_feedback = await self.review_sched.run_global_review(
                        advisors_def=self.wf.roles.advisors,
                        task_file=ctx.task_file,
                        summary_file=ctx.summary_file,
                        results_dir=ctx.results_dir,
                        work_dir=work_dir,
                        cycle=cycle,
                        review_state=review_state,
                        advisor_sessions=ctx.advisor_sessions,
                        engine_config=self.wf.engine,
                    )

            global_cycle_records = review_state.get_global_review_records(cycle)
            global_advisor_results = [
                {
                    "advisor_id": item.advisor_id,
                    "role_name": item.role_name,
                    "passed": item.passed,
                    "feedback_preview": item.feedback[:300],
                }
                for item in global_cycle_records
            ]
            for item in global_advisor_results:
                vlog.global_review_advisor_result(
                    item["advisor_id"],
                    item["role_name"],
                    bool(item["passed"]),
                    str(item["feedback_preview"]),
                )
            vlog.global_review_result(
                global_passed,
                global_advisor_results,
                global_feedback[:100],
            )

            # ── 6. 结果评审（即使 global review 不通过，也尽量冻结已通过结果，保证单调增长） ──
            await self._transition_state(ctx, AtomicWorkflowState.RESULT_REVIEW)
            all_results = list_result_report_files(ctx.results_dir)
            current_fingerprints = calculate_result_fingerprints(ctx.results_dir)
            advisors_dicts = [a.model_dump() for a in self.wf.roles.advisors.result_review]
            pending = review_state.get_pending_results(
                all_results,
                advisors_dicts,
                current_fingerprints,
            )
            vlog.result_review_start(cycle, len(all_results), len(pending))

            try:
                result_passed, failed_items = await self.review_sched.run_result_review(
                    advisors_def=self.wf.roles.advisors,
                    task_file=ctx.task_file,
                    results_dir=ctx.results_dir,
                    work_dir=work_dir,
                    cycle=cycle,
                    review_state=review_state,
                    parallel=self.global_cfg.parallel_result_review,
                    concurrency_limit=self.global_cfg.parallel_result_review_limit,
                    advisor_sessions=ctx.advisor_sessions,
                )
            except ResultReviewFrameworkError as exc:
                error = f"结果评审框架错误：{exc}"
                await self.recorder.record_warning(work_dir, error)
                await self._transition_state(
                    ctx,
                    AtomicWorkflowState.FAILED,
                    detail=error,
                )
                logger.error(
                    "result_review_framework_error",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=cycle,
                    result_file=exc.result_file,
                    advisor_id=exc.advisor_id,
                    error_code=exc.error_code,
                    error=exc.reason,
                )
                return AtomicWorkflowResult(
                    status=self._classify_terminal_status(error, default="review_error"),
                    error=error,
                    working_dir=ctx.working_dir,
                    cycles_used=ctx.cycle,
                )

            # 打印每个结果的评审情况
            for f in all_results:
                if review_state.is_result_passed(f, current_fingerprints.get(f)):
                    vlog.result_review_item(f, True)
                else:
                    state = review_state.result_states.get(f)
                    reason = state.failure_reason[:80] if state else ""
                    vlog.result_review_item(f, False, reason)

            passed_files = [
                f for f in all_results
                if review_state.is_result_passed(f, current_fingerprints.get(f))
            ]
            passed_count = len(passed_files)
            failed_count = len(all_results) - passed_count
            vlog.result_review_summary(passed_count, failed_count)

            failed_dicts = [
                {"filename": fi.filename, "reason": fi.reason}
                for fi in failed_items
            ]

            global_passed, global_feedback = self._apply_profile_min_discovery_gate(
                ctx=ctx,
                review_state=review_state,
                cycle=cycle,
                global_passed=global_passed,
                global_feedback=global_feedback,
                result_passed=result_passed,
            )
            prelim_failure_scope = self._classify_global_failure_scope(review_state)
            summary_repair_routed = (
                result_passed
                and not global_passed
                and prelim_failure_scope == "summary_or_ledger"
            )
            summary_repair_reason = "结果评审已通过，剩余问题集中在 summary/ledger 同步"
            if summary_repair_routed:
                ctx.pending_summary_repair = True
                ctx.review_mode = "closure"
                review_state.workflow_mode = "closure"

            cycle_metrics = self._build_cycle_metrics(
                ctx=ctx,
                review_state=review_state,
                cycle=cycle,
                global_passed=global_passed,
                global_feedback=global_feedback,
                all_results=all_results,
                passed_files=passed_files,
                failed_items=failed_items,
                failed_count=failed_count,
                current_fingerprints=current_fingerprints,
            )
            ctx.issue_ledger_status = dict(cycle_metrics.get("issue_ledger_status") or {})
            cycle_metrics_history.append(cycle_metrics)
            plateau_status = self._update_plateau_state(
                ctx=ctx,
                review_state=review_state,
                metrics_history=cycle_metrics_history,
            )
            self._write_cycle_metrics(
                work_dir=work_dir,
                cycle=cycle,
                metrics=cycle_metrics,
                plateau_status=plateau_status,
            )
            self._write_issue_ledger(work_dir=work_dir, review_state=review_state)

            await self.recorder.record_review_cycle_summary(
                work_dir=work_dir,
                cycle=cycle,
                global_passed=global_passed,
                global_feedback=global_feedback,
                total_results=len(all_results),
                passed_results=passed_files,
                failed_results=failed_dicts,
                workflow_mode=ctx.review_mode,
                issues=review_state.get_recent_issues(last_n=1),
                plateau_status=plateau_status,
                global_advisor_results=global_advisor_results,
            )

            if not global_passed:
                review_state.record_global_failure(cycle, global_feedback)
            if not result_passed:
                review_state.record_result_failures(
                    failed_items,
                    cycle,
                    file_fingerprints=current_fingerprints,
                )
                ctx.failed_result_items = failed_items
            else:
                ctx.failed_result_items = []

            if global_passed and result_passed:
                ctx.plateau_streak = 0
                ctx.plateau_reason = ""
                ctx.pending_summary_repair = False
                ctx.summary_repair_attempts = 0
                logger.info("all_reviews_passed", cycle=cycle, mode=ctx.review_mode)
                return None

            failure_scope = str(cycle_metrics.get("global_failure_scope") or "")
            if not global_passed and failure_scope == "framework":
                error = "全局评审存在框架/Advisor 契约错误，不能交给 Worker 做 closure/summary 修复"
                await self.recorder.record_warning(work_dir, error)
                await self._transition_state(
                    ctx,
                    AtomicWorkflowState.FAILED,
                    detail=error,
                )
                logger.error(
                    "global_review_framework_failure",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=cycle,
                    feedback=global_feedback[:500],
                )
                return AtomicWorkflowResult(
                    status="review_error",
                    error=error,
                    working_dir=ctx.working_dir,
                    cycles_used=ctx.cycle,
                )

            if summary_repair_routed:
                ctx.plateau_reason = summary_repair_reason
                review_state.activate_closure_mode(cycle, summary_repair_reason)
                logger.info(
                    "route_global_failure_to_summary_repair",
                    cycle=cycle,
                    mode=ctx.review_mode,
                    reason=ctx.plateau_reason,
                    attempts_used=ctx.summary_repair_attempts,
                    attempt_budget=getattr(self.wf.engine, "summary_repair_attempt_budget", 2),
                )

            if plateau_status.get("abort"):
                error = str(plateau_status.get("reason") or "评审进入停滞状态，提前终止")
                await self.recorder.record_warning(work_dir, error)
                await self._transition_state(
                    ctx,
                    AtomicWorkflowState.FAILED,
                    detail=error,
                )
                return AtomicWorkflowResult(
                    status=str(plateau_status.get("terminal_status") or "review_plateau"),
                    error=error,
                    working_dir=ctx.working_dir,
                    cycles_used=ctx.cycle,
                )

            if not global_passed:
                logger.info(
                    "global_review_failed_retry",
                    cycle=cycle,
                    feedback=global_feedback[:200],
                    mode=ctx.review_mode,
                    issues=0,
                )
            if not result_passed:
                logger.info(
                    "result_review_failed_retry",
                    cycle=cycle,
                    failed_count=len(failed_items),
                    mode=ctx.review_mode,
                )

        error = f"达到最大评审循环次数 {total_cycle_limit}，仍未通过评审"
        if cycle_metrics_history:
            last = cycle_metrics_history[-1]
            if (
                not last.get("global_passed")
                and int(last.get("failed_result_count") or 0) == 0
                and last.get("global_failure_scope") == "summary_or_ledger"
            ):
                error = (
                    f"达到最大评审循环次数 {total_cycle_limit}，结果评审已通过，"
                    "但 summary/ledger 同步仍未通过"
                )
        await self.recorder.record_warning(work_dir, error)
        await self._transition_state(
            ctx,
            AtomicWorkflowState.FAILED,
            detail=error,
        )
        terminal_status = "summary_incomplete" if "summary/ledger" in error else "failed"
        if cycle_metrics_history:
            last_status = cycle_metrics_history[-1].get("issue_ledger_status") or {}
            dominant_issue = last_status.get("dominant_issue") or None
            plateau_like_status = self._classify_plateau_terminal_status(
                cycle_metrics_history[-1],
                dominant_issue,
            )
            if plateau_like_status != "review_plateau":
                terminal_status = plateau_like_status
        return AtomicWorkflowResult(
            status=terminal_status,
            error=error,
            working_dir=ctx.working_dir,
            cycles_used=ctx.cycle,
        )

    def _build_cycle_metrics(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        cycle: int,
        global_passed: bool,
        global_feedback: str,
        all_results: list[str],
        passed_files: list[str],
        failed_items: list,
        failed_count: int,
        current_fingerprints: dict[str, str] | None = None,
    ) -> dict:
        summary_size = 0
        summary_fingerprint = ""
        if ctx.summary_file and os.path.isfile(ctx.summary_file):
            try:
                summary_size = os.path.getsize(ctx.summary_file)
                summary_fingerprint = self._file_sha256(ctx.summary_file)
            except OSError:
                summary_size = 0

        recent_issues = review_state.get_recent_issues(last_n=1)
        current_failed_files = [item.filename for item in failed_items]
        unreviewed_new_results = [
            name for name in all_results
            if name not in set(passed_files) and name not in set(current_failed_files)
        ]
        historical_removed_result_count = self._count_removed_result_backups(ctx.working_dir)
        current_fingerprints = current_fingerprints or {}
        result_fingerprint_digest = self._result_fingerprint_digest(current_fingerprints)
        supporting_docs_dir = os.path.join(ctx.working_dir, "supporting_docs")
        supporting_docs_fingerprint = self._markdown_tree_digest(supporting_docs_dir)
        supporting_docs_count = self._count_markdown_files(supporting_docs_dir)
        issue_ledger_status = review_state.get_issue_ledger_status()
        return {
            "cycle": cycle,
            "workflow_mode": ctx.review_mode,
            "global_passed": global_passed,
            "global_feedback_preview": (global_feedback or "")[:300],
            "scores": dict(review_state.last_global_scores or {}),
            "global_scores": dict(review_state.last_global_scores or {}),
            "global_failure_scope": self._classify_global_failure_scope(review_state),
            "issue_count": len(recent_issues),
            "issue_ids": [item.get("detail", "")[:80] for item in recent_issues],
            "total_results": len(all_results),
            "passed_result_count": len(passed_files),
            "failed_result_count": failed_count,
            "current_failed_result_count": len(current_failed_files),
            "current_failed_result_files": current_failed_files,
            "historical_removed_result_count": historical_removed_result_count,
            "unreviewed_new_result_count": len(unreviewed_new_results),
            "unreviewed_new_result_files": unreviewed_new_results,
            "result_fingerprint_digest": result_fingerprint_digest,
            "result_files": list(all_results),
            "summary_size": summary_size,
            "summary_fingerprint": summary_fingerprint,
            "supporting_docs_count": supporting_docs_count,
            "supporting_docs_fingerprint": supporting_docs_fingerprint,
            "issue_ledger_status": issue_ledger_status,
            "issue_signatures": list(issue_ledger_status.get("repeated_signatures") or []),
        }

    @staticmethod
    def _classify_global_failure_scope(review_state: ReviewState) -> str:
        issues = review_state.get_recent_issues(last_n=1)
        if not issues:
            scores = review_state.last_global_scores or {}
            if scores and all(
                key in {"limitations_honesty", "report_completeness"}
                for key in scores
            ):
                return "summary_or_ledger"
            return "unknown"
        actionable = {
            str(item.get("actionable_by") or item.get("owner") or "").strip().lower()
            for item in issues
            if str(item.get("actionable_by") or item.get("owner") or "").strip()
        }
        categories = {
            str(item.get("category") or "").strip().lower()
            for item in issues
            if str(item.get("category") or "").strip()
        }
        if actionable == {"framework"}:
            return "framework"
        if actionable:
            if actionable <= {"report", "summary", "ledger"}:
                return "summary_or_ledger"
            return "analysis"
        report_categories = {
            "report_completeness",
            "limitations_honesty",
            "summary",
            "ledger",
            "metadata",
            "metadata_sync",
        }
        if categories and categories <= report_categories:
            return "summary_or_ledger"
        return "analysis"

    @staticmethod
    def _result_fingerprint_digest(fingerprints: dict[str, str]) -> str:
        if not fingerprints:
            return ""
        h = hashlib.sha256()
        for name, digest in sorted(fingerprints.items()):
            h.update(name.encode("utf-8", errors="replace"))
            h.update(b"=")
            h.update(str(digest).encode("utf-8", errors="replace"))
            h.update(b"\n")
        return h.hexdigest()

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def _markdown_tree_digest(cls, dir_path: str) -> str:
        root = Path(dir_path)
        if not root.is_dir():
            return ""
        h = hashlib.sha256()
        found = False
        for path in sorted(root.glob("*.md")):
            if not path.is_file():
                continue
            found = True
            rel = path.name
            h.update(rel.encode("utf-8", errors="replace"))
            h.update(b"=")
            try:
                h.update(cls._file_sha256(str(path)).encode("utf-8"))
            except OSError:
                h.update(b"<unreadable>")
            h.update(b"\n")
        return h.hexdigest() if found else ""

    @staticmethod
    def _count_markdown_files(dir_path: str) -> int:
        root = Path(dir_path)
        if not root.is_dir():
            return 0
        return len([path for path in root.glob("*.md") if path.is_file()])

    def _update_plateau_state(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        metrics_history: list[dict],
    ) -> dict:
        engine_cfg = getattr(getattr(self, "wf", None), "engine", None)
        profile_policy = get_review_profile_policy(ctx.review_profile)

        def cfg_int(name: str, default: int) -> int:
            try:
                return int(getattr(engine_cfg, name, default))
            except (TypeError, ValueError):
                return default

        def cfg_float(name: str, default: float) -> float:
            try:
                return float(getattr(engine_cfg, name, default))
            except (TypeError, ValueError):
                return default

        closure_streak_threshold = cfg_int("plateau_closure_streak", 2)
        abort_streak_threshold = cfg_int("plateau_abort_streak", 3)
        progress_required_after_cycle = cfg_int(
            "progress_required_after_cycle",
            profile_policy.progress_required_after_cycle,
        )
        progress_no_signal_closure_streak = cfg_int(
            "progress_no_signal_closure_streak",
            profile_policy.progress_no_signal_closure_streak,
        )
        progress_no_signal_abort_streak = cfg_int(
            "progress_no_signal_abort_streak",
            profile_policy.progress_no_signal_abort_streak,
        )
        same_issue_stagnation_threshold = cfg_int("same_issue_stagnation_threshold", 2)
        same_issue_abort_threshold = cfg_int("same_issue_abort_threshold", 3)
        per_issue_attempt_budget = cfg_int("per_issue_attempt_budget", 2)
        summary_repair_attempt_budget = cfg_int("summary_repair_attempt_budget", 2)
        analysis_closure_cycles = cfg_int("analysis_closure_cycles", 1)
        issue_churn_closure_window = cfg_int("issue_churn_closure_window", 2)
        issue_churn_abort_window = cfg_int("issue_churn_abort_window", 3)
        score_min_delta = cfg_float("score_min_delta", 0.03)

        if not metrics_history:
            return {
                "stagnant": False,
                "streak": ctx.plateau_streak,
                "workflow_mode": ctx.review_mode,
                "issue_ledger_status": review_state.get_issue_ledger_status(),
            }

        current = metrics_history[-1]
        progress_gate_active = (
            progress_required_after_cycle > 0
            and int(current.get("cycle") or 0) >= progress_required_after_cycle
        )
        if progress_required_after_cycle > 0:
            if progress_gate_active:
                closure_streak_threshold = min(
                    closure_streak_threshold,
                    progress_no_signal_closure_streak,
                )
                abort_streak_threshold = min(
                    abort_streak_threshold,
                    progress_no_signal_abort_streak,
                )
            else:
                closure_streak_threshold = max(closure_streak_threshold, 2)
                abort_streak_threshold = max(abort_streak_threshold, 3)
        if current["global_passed"] and current["failed_result_count"] == 0:
            ctx.plateau_streak = 0
            ctx.plateau_reason = ""
            return {
                "stagnant": False,
                "streak": 0,
                "workflow_mode": ctx.review_mode,
                "issue_ledger_status": current.get("issue_ledger_status") or {},
            }

        if len(metrics_history) < 2:
            return {
                "stagnant": False,
                "streak": ctx.plateau_streak,
                "workflow_mode": ctx.review_mode,
                "issue_ledger_status": current.get("issue_ledger_status") or {},
            }

        prev = metrics_history[-2]

        # 分数停滞检测：小于最小有效增量的变化不再重置 plateau。
        current_scores = current.get("global_scores") or current.get("scores") or {}
        prev_scores = prev.get("global_scores") or prev.get("scores") or {}
        max_score_gain = self._max_score_gain(prev_scores, current_scores)
        scores_not_improved = (
            bool(current_scores) and bool(prev_scores)
            and max_score_gain < score_min_delta
        )

        current_failed_files = sorted(current.get("current_failed_result_files") or [])
        prev_failed_files = sorted(prev.get("current_failed_result_files") or [])
        failed_result_ids_unchanged = (
            bool(current_failed_files)
            and current_failed_files == prev_failed_files
        )

        current_digest = str(current.get("result_fingerprint_digest") or "")
        prev_digest = str(prev.get("result_fingerprint_digest") or "")
        result_content_unchanged = bool(current_digest) and current_digest == prev_digest
        result_set_unchanged = list(current.get("result_files") or []) == list(prev.get("result_files") or [])
        result_artifacts_unchanged = result_content_unchanged or (
            result_set_unchanged
            and current.get("total_results") == prev.get("total_results")
            and current.get("historical_removed_result_count") == prev.get("historical_removed_result_count")
        )
        summary_artifact_unchanged = (
            str(current.get("summary_fingerprint") or "") == str(prev.get("summary_fingerprint") or "")
            and int(current.get("summary_size") or 0) == int(prev.get("summary_size") or 0)
        )
        supporting_docs_unchanged = (
            str(current.get("supporting_docs_fingerprint") or "") == str(prev.get("supporting_docs_fingerprint") or "")
            and int(current.get("supporting_docs_count") or 0) == int(prev.get("supporting_docs_count") or 0)
        )
        passed_not_grown = current["passed_result_count"] <= prev["passed_result_count"]
        no_new_unreviewed_results = int(current.get("unreviewed_new_result_count") or 0) == 0
        failure_scope = str(current.get("global_failure_scope") or "")

        issue_status = current.get("issue_ledger_status") or {}
        prev_issue_status = prev.get("issue_ledger_status") or {}
        active_issue_not_decreased = (
            int(issue_status.get("active_issue_count") or 0)
            >= int(prev_issue_status.get("active_issue_count") or 0)
        )
        current_issue_not_decreased = (
            int(issue_status.get("current_issue_count") or 0)
            >= int(prev_issue_status.get("current_issue_count") or 0)
        )
        dominant_issue = issue_status.get("dominant_issue") or None
        try:
            max_issue_consecutive = int(issue_status.get("max_consecutive_count") or 0)
        except (TypeError, ValueError):
            max_issue_consecutive = 0
        same_issue_repeated = max_issue_consecutive >= same_issue_stagnation_threshold
        same_issue_over_budget = (
            max_issue_consecutive >= same_issue_abort_threshold
            or max_issue_consecutive > per_issue_attempt_budget
        )
        result_review_passed = int(current.get("failed_result_count") or 0) == 0
        issue_churn_detected = self._issue_churn_detected(
            metrics_history,
            window=issue_churn_closure_window,
        )
        issue_churn_over_budget = self._issue_churn_detected(
            metrics_history,
            window=issue_churn_abort_window,
        )
        summary_repair_budget_available = (
            failure_scope == "summary_or_ledger"
            and result_review_passed
            and not current.get("global_passed")
            and ctx.summary_repair_attempts < summary_repair_attempt_budget
        )

        stable_score_failure = scores_not_improved
        stable_result_failure = failed_result_ids_unchanged and result_artifacts_unchanged
        summary_freshness_failure = (
            failure_scope == "summary_or_ledger"
            and summary_artifact_unchanged
            and supporting_docs_unchanged
        )
        same_issue_failure = (
            same_issue_repeated
            and result_artifacts_unchanged
            and passed_not_grown
            and no_new_unreviewed_results
            and (
                scores_not_improved
                or supporting_docs_unchanged
                or ctx.review_mode == "closure"
            )
        )
        issue_churn_failure = (
            issue_churn_detected
            and result_review_passed
            and passed_not_grown
            and no_new_unreviewed_results
        )
        score_no_signal = scores_not_improved or not current_scores or not prev_scores
        no_effective_progress_failure = (
            progress_gate_active
            and result_artifacts_unchanged
            and supporting_docs_unchanged
            and passed_not_grown
            and no_new_unreviewed_results
            and score_no_signal
            and active_issue_not_decreased
            and current_issue_not_decreased
        )

        reasons: list[str] = []
        if no_effective_progress_failure:
            reasons.append(
                "audit 有效进展信号不足：未新增/修正 result，supporting_docs 未变化，"
                "通过结果未增长，issue/coverage 未收敛，且全局评分无有效提升"
            )
        if scores_not_improved:
            reasons.append(f"全局评审分数有效提升不足（max_gain={max_score_gain:.3f} < {score_min_delta:.3f}）")
        if stable_result_failure:
            reasons.append("失败结果文件未变化")
        if result_artifacts_unchanged:
            reasons.append("result 文件集合/内容未变化")
        if summary_artifact_unchanged:
            reasons.append("summary.md 未变化")
        if supporting_docs_unchanged:
            reasons.append("supporting_docs 未变化")
        if passed_not_grown:
            reasons.append("已冻结通过结果数量未增长")
        if no_new_unreviewed_results:
            reasons.append("没有新增待评审结果")
        if same_issue_repeated:
            signature = str((dominant_issue or {}).get("signature") or "")
            reasons.append(f"同一全局评审 issue 连续出现 {max_issue_consecutive} 轮：{signature}")
        if issue_churn_detected:
            reasons.append(
                f"全局评审 issue 在最近 {issue_churn_closure_window} 个 cycle 中持续轮换，"
                "result review 已稳定但 global blocker 未形成固定收敛队列"
            )
        if summary_freshness_failure:
            reasons.append("summary/ledger 类失败未带来正式文档变化")

        stagnant = (
            (stable_score_failure or stable_result_failure)
            and result_artifacts_unchanged
            and passed_not_grown
            and no_new_unreviewed_results
        ) or same_issue_failure or summary_freshness_failure or issue_churn_failure or no_effective_progress_failure

        switched_to_closure = False
        abort = False
        terminal_status = "review_plateau"
        if stagnant:
            ctx.plateau_streak += 1
            ctx.plateau_reason = "；".join(reasons) or "评审停滞"
        else:
            ctx.plateau_streak = 0
            ctx.plateau_reason = ""

        should_enter_closure = (
            stagnant and ctx.plateau_streak >= closure_streak_threshold
        ) or (
            result_review_passed
            and not current.get("global_passed")
            and failure_scope in {"analysis", "summary_or_ledger", "unknown"}
            and same_issue_repeated
        ) or (
            issue_churn_detected
            and result_review_passed
            and not current.get("global_passed")
        )
        if should_enter_closure and ctx.review_mode != "closure":
            ctx.review_mode = "closure"
            review_state.activate_closure_mode(current["cycle"], ctx.plateau_reason)
            switched_to_closure = True
            logger.warning(
                "review_plateau_detected_enter_closure",
                cycle=current["cycle"],
                streak=ctx.plateau_streak,
                reason=ctx.plateau_reason,
            )
        else:
            review_state.workflow_mode = ctx.review_mode

        closure_since = review_state.closure_since_cycle
        closure_age = (
            int(current["cycle"]) - int(closure_since)
            if closure_since is not None else
            0
        )
        analysis_closure_expired = (
            failure_scope == "analysis"
            and result_review_passed
            and same_issue_repeated
            and closure_age >= analysis_closure_cycles
        )

        would_abort = (
            ctx.review_mode == "closure"
            and not switched_to_closure
            and (
                (stagnant and ctx.plateau_streak >= abort_streak_threshold)
                or (same_issue_over_budget and closure_age >= 1)
                or (issue_churn_over_budget and closure_age >= 1)
                or (analysis_closure_expired and stagnant)
            )
        )
        if would_abort and summary_repair_budget_available:
            logger.info(
                "summary_repair_defer_plateau_abort",
                cycle=current["cycle"],
                attempts_used=ctx.summary_repair_attempts,
                attempt_budget=summary_repair_attempt_budget,
                failure_scope=failure_scope,
            )
        elif would_abort:
            abort = True
            terminal_status = self._classify_plateau_terminal_status(current, dominant_issue)

        abort_reason = ctx.plateau_reason
        if abort:
            if abort_reason:
                abort_reason = (
                    f"评审在 {ctx.plateau_streak} 个连续 cycle 中停滞，"
                    f"且进入 closure 模式后仍未收敛：{abort_reason}"
                )
            elif issue_churn_over_budget:
                abort_reason = (
                    f"closure 模式下全局评审 issue 在最近 {issue_churn_abort_window} 个 cycle 中持续轮换，"
                    "且没有形成可收敛的固定修复队列"
                )
            elif same_issue_over_budget:
                abort_reason = (
                    f"同一全局评审 issue 已超过尝试预算（max_consecutive={max_issue_consecutive}）"
                )
            else:
                abort_reason = "closure 模式下评审停滞超过预算"
        elif summary_repair_budget_available:
            abort_reason = (
                f"summary/ledger repair pending "
                f"({ctx.summary_repair_attempts}/{summary_repair_attempt_budget})"
            )

        return {
            "stagnant": stagnant,
            "streak": ctx.plateau_streak,
            "workflow_mode": ctx.review_mode,
            "switched_to_closure": switched_to_closure,
            "abort": abort,
            "terminal_status": terminal_status,
            "score_min_delta": score_min_delta,
            "max_score_gain": max_score_gain,
            "progress_required_after_cycle": progress_required_after_cycle,
            "progress_gate_active": progress_gate_active,
            "no_effective_progress_failure": no_effective_progress_failure,
            "summary_artifact_unchanged": summary_artifact_unchanged,
            "supporting_docs_unchanged": supporting_docs_unchanged,
            "same_issue_repeated": same_issue_repeated,
            "same_issue_over_budget": same_issue_over_budget,
            "issue_churn_detected": issue_churn_detected,
            "issue_churn_over_budget": issue_churn_over_budget,
            "summary_repair_attempts": ctx.summary_repair_attempts,
            "summary_repair_attempt_budget": summary_repair_attempt_budget,
            "summary_repair_deferred_abort": bool(would_abort and summary_repair_budget_available),
            "issue_ledger_status": issue_status,
            "reason": abort_reason,
        }

    @staticmethod
    def _max_score_gain(previous: dict, current: dict) -> float:
        keys = set(previous.keys()) | set(current.keys())
        if not keys:
            return 0.0
        gains = []
        for key in keys:
            try:
                gains.append(float(current.get(key, 0.0)) - float(previous.get(key, 0.0)))
            except (TypeError, ValueError):
                gains.append(0.0)
        return max(gains) if gains else 0.0

    @staticmethod
    def _issue_churn_detected(metrics_history: list[dict], *, window: int) -> bool:
        """Detect serially changing global blockers after result review stabilizes."""
        if window < 2 or len(metrics_history) < window:
            return False
        recent = metrics_history[-window:]
        signature_sets: list[tuple[str, ...]] = []
        for item in recent:
            if item.get("global_passed"):
                return False
            if int(item.get("failed_result_count") or 0) != 0:
                return False
            issue_status = item.get("issue_ledger_status") or {}
            signatures = issue_status.get("current_signatures") or []
            if not signatures:
                dominant = issue_status.get("dominant_issue") or {}
                signature = str(dominant.get("signature") or "").strip()
                signatures = [signature] if signature else []
            normalized = tuple(sorted(str(sig) for sig in signatures if str(sig).strip()))
            if not normalized:
                return False
            signature_sets.append(normalized)

        distinct_sets = set(signature_sets)
        if len(distinct_sets) < window:
            return False
        for previous, current in zip(signature_sets, signature_sets[1:]):
            if set(previous) & set(current):
                return False
        return True

    @staticmethod
    def _classify_plateau_terminal_status(current_metrics: dict, dominant_issue: dict | None) -> str:
        failure_scope = str(current_metrics.get("global_failure_scope") or "")
        if failure_scope == "summary_or_ledger":
            return "summary_incomplete"

        issue = dominant_issue or {}
        blocking_type = str(issue.get("blocking_type") or "").strip().lower()
        nested_issue = issue.get("issue") if isinstance(issue.get("issue"), dict) else {}
        detail = " ".join(
            str(issue.get(key) or "")
            for key in ("acceptance_criteria", "external_dependency", "semantic_key")
        )
        detail += " " + " ".join(
            str(nested_issue.get(key) or "")
            for key in ("detail", "required_action", "external_dependency")
        )
        detail = detail.lower()
        external_markers = {
            "needs_external_source",
            "external_source_missing",
            "source_unavailable",
            "unverifiable_external",
            "blocked_external_source",
        }
        if blocking_type in external_markers:
            return "blocked_external_source"
        if (
            ("external" in detail and ("source" in detail or "dependency" in detail))
            or "源码不可得" in detail
            or "外部依赖" in detail
            or "不可闭环" in detail
        ):
            return "blocked_external_source"
        return "review_plateau"

    @staticmethod
    def _count_removed_result_backups(work_dir: str) -> int:
        removed_root = Path(work_dir) / "removed_results"
        if not removed_root.is_dir():
            return 0
        return len(sorted(removed_root.glob("cycle_*/result_*.md")))

    def _write_cycle_metrics(
        self,
        *,
        work_dir: str,
        cycle: int,
        metrics: dict,
        plateau_status: dict,
    ) -> None:
        metrics_dir = os.path.join(work_dir, "_meta", "cycle_metrics")
        os.makedirs(metrics_dir, exist_ok=True)
        write_json(
            os.path.join(metrics_dir, f"cycle_{cycle:03d}.json"),
            {
                **metrics,
                "plateau_status": plateau_status,
            },
        )

    @staticmethod
    def _write_issue_ledger(
        *,
        work_dir: str,
        review_state: ReviewState,
    ) -> None:
        meta_dir = os.path.join(work_dir, "_meta")
        os.makedirs(meta_dir, exist_ok=True)
        write_json(
            os.path.join(meta_dir, "issue_ledger.json"),
            review_state.get_issue_ledger_snapshot(),
        )

    async def _precheck_result_granularity(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> None:
        """Summary 后立即检测多漏洞打包，标记为失败以便 Worker 下轮修复。"""
        results_dir = ctx.results_dir
        if not results_dir or not os.path.isdir(results_dir):
            return
        multi_finding_reports = collect_multi_finding_result_reports(results_dir)
        if not multi_finding_reports:
            return
        current_fingerprints = calculate_result_fingerprints(results_dir)
        for result_file, vuln_ids in multi_finding_reports.items():
            reason = (
                "结果文件包含多个独立漏洞条目，破坏了 result review / freeze / 下游任务的最小粒度。"
                f" 请将 {result_file} 拆分为多个独立的 `result_NNN.md`；"
                f" 当前检测到的漏洞标题：{', '.join(vuln_ids)}"
            )
            await self.recorder.record_result_review(
                work_dir=ctx.working_dir,
                result_file=result_file,
                advisor_id="framework_result_shape",
                cycle=ctx.cycle,
                passed=False,
                content=reason,
                verdict="ERROR",
                detail_feedback=reason,
                schema_valid=False,
                parser_mode="framework_precheck",
                repair_attempts=0,
            )
            review_state.mark_result_failed(
                result_file,
                ctx.cycle,
                reason,
                current_fingerprints.get(result_file, ""),
            )
            logger.warning(
                "multi_finding_result_detected",
                result_file=result_file,
                vuln_ids=vuln_ids,
                cycle=ctx.cycle,
            )

    async def _run_end_and_collect(self, ctx):
        vlog.section("🔌", "结束插件链", f"{len(self.wf.end_plugins)} 个插件")
        await self._transition_state(ctx, AtomicWorkflowState.END_PLUGINS)

        end_result = await self._run_plugins(self.wf.end_plugins, ctx, "end")
        if end_result.action == "restart_workflow":
            return AtomicWorkflowResult(
                status="failed", action="restart_workflow",
                working_dir=ctx.working_dir)
        if end_result.action == "exit_workflow":
            return AtomicWorkflowResult(
                status="failed", error=end_result.error,
                working_dir=ctx.working_dir)

        next_tasks = self._collect_next_tasks(ctx.working_dir)
        await self._transition_state(ctx, AtomicWorkflowState.COMPLETED)

        return AtomicWorkflowResult(
            status="completed", next_tasks=next_tasks,
            working_dir=ctx.working_dir)

    async def _run_plugins(self, plugin_ids, ctx, phase):
        base_ctx = PluginContext(
            workflow_id=ctx.workflow_id, task_id=ctx.task_id,
            execution_id=ctx.task_id, working_dir=ctx.working_dir,
            task_file=ctx.task_file, plugin_config={},
            shared_state={}, global_config=self.global_cfg.model_dump(),
            cycle_number=ctx.cycle, summary_file=ctx.summary_file,
            results_dir=ctx.results_dir,
            review_records_dir=os.path.join(ctx.working_dir, "reviews"),
            agent_registry=self.agents)
        result = await self.plugin_exec.execute_chain(
            plugin_ids, base_ctx, phase, recorder=self.recorder)
        # 可视化每个插件结果
        for pr in result.results:
            vlog.plugin_executed(
                pr.data.get("plugin_id", ""), phase, pr.code.value, pr.message)
        return result

    def _collect_next_tasks(self, work_dir: str) -> list[TaskItem]:
        output_dir = os.path.join(work_dir, "output")
        index_file = os.path.join(output_dir, "next_tasks.json")

        if os.path.exists(index_file):
            try:
                data = read_json(index_file)
                return [
                    TaskItem(
                        id=t.get("id", t.get("task_id", "")),
                        file=t.get("file", ""),
                        source_stage=self.wf.id)
                    for t in data.get("tasks", [])
                ]
            except Exception as e:
                logger.warning("next_tasks_parse_error", error=str(e))

        if os.path.isdir(output_dir):
            md_files = sorted(f for f in os.listdir(output_dir)
                              if f.endswith(".md"))
            return [
                TaskItem(id=Path(f).stem,
                         file=os.path.join(output_dir, f),
                         source_stage=self.wf.id)
                for f in md_files
            ]
        return []
