"""
原子工作流引擎

完整生命周期：
启动插件 → Worker → 反思 → 总结 → 全局评审 → 结果评审 → (循环) → 结束插件
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef, GlobalConfig
from app.pi_vuln_core.engine.models import (
    AtomicWorkflowState, AtomicWorkflowResult,
    WorkflowContext, TaskItem,
)
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.plugins.base import PluginContext
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.scheduler import ReviewScheduler
from app.pi_vuln_core.review.state import ReviewState, calculate_result_fingerprints
from app.pi_vuln_core.workspace.manager import WorkspaceManager
from app.pi_vuln_core.utils.file_ops import read_json, copy_file, list_dir_files, write_json
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.result_docs import list_result_report_files
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

        max_retry = self.global_cfg.max_workflow_retry
        for attempt in range(1, max_retry + 1):
            result = await self._execute_once(work_dir, input_task, task_id)
            if result.action == "restart_workflow":
                logger.warning("workflow_restart",
                               workflow_id=self.wf.id, attempt=attempt)
                if attempt >= max_retry:
                    result.status = "failed"
                    result.error = f"超过最大重试次数 ({max_retry})"
                    break
                continue
            else:
                break

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
            worker_session_id=worker_session_id,
            advisor_sessions=advisor_sessions or {},
            summary_file=(os.path.join(work_dir, "summary.md")
                          if os.path.isfile(os.path.join(work_dir, "summary.md")) else None),
            results_dir=(os.path.join(work_dir, "results")
                         if os.path.isdir(os.path.join(work_dir, "results")) else None),
            review_mode=review_state.workflow_mode,
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
        )

        cycle_result = await self._run_review_cycles(
            ctx,
            review_state,
            start_cycle=start_cycle,
            total_cycle_limit=total_cycle_limit,
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

    async def _execute_once(
        self, work_dir: str, task_file: str, task_id: str,
    ) -> AtomicWorkflowResult:

        ctx = WorkflowContext(
            workflow_id=self.wf.id, task_id=task_id,
            task_file=task_file, working_dir=work_dir)

        # ═══ 阶段1: 启动插件 ═══
        vlog.section("🔌", "启动插件链", f"{len(self.wf.start_plugins)} 个插件")
        await self.recorder.record_state_change(
            work_dir, "", AtomicWorkflowState.START_PLUGINS.value)

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

    async def _run_review_cycles(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
        *,
        start_cycle: int,
        total_cycle_limit: int,
    ) -> AtomicWorkflowResult | None:
        work_dir = ctx.working_dir
        cycle_metrics_history: list[dict] = []
        review_state.workflow_mode = ctx.review_mode

        for cycle in range(start_cycle + 1, total_cycle_limit + 1):
            ctx.cycle = cycle
            review_state.workflow_mode = ctx.review_mode
            vlog.cycle_start(cycle, total_cycle_limit)

            # ── 2. Worker 执行 ──
            vlog.worker_start(cycle)
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.WORKER.value,
                detail=f"cycle={cycle},mode={ctx.review_mode}")
            await self.worker_exec.execute_worker(self.wf, ctx, review_state)
            vlog.worker_done(1)

            # ── 3. 自我反思 ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.REFLECT.value)
            for i, r in enumerate(self.wf.roles.worker.prompts.reflection):
                vlog.reflection_start(i + 1, r.id)
            await self.worker_exec.execute_reflection(self.wf, ctx, review_state)
            if self.wf.roles.worker.prompts.reflection:
                vlog.reflection_done(len(self.wf.roles.worker.prompts.reflection))

            # ── 4. 总结 ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.SUMMARY.value)
            summary_path, results_dir = \
                await self.worker_exec.execute_summary(self.wf, ctx)
            # 如果 Worker 未生成 summary.md，创建占位文件，让全局评审正常进行（会判不通过并打回）
            if not os.path.isfile(summary_path):
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

            # ── 5. 全局评审 ──
            global_advisors = self.wf.roles.advisors.global_review
            vlog.global_review_start(cycle, len(global_advisors))
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.GLOBAL_REVIEW.value)

            global_passed, global_feedback = await self.review_sched.run_global_review(
                advisors_def=self.wf.roles.advisors,
                task_file=ctx.task_file,
                summary_file=ctx.summary_file,
                results_dir=ctx.results_dir,
                work_dir=work_dir,
                cycle=cycle,
                review_state=review_state,
                advisor_sessions=ctx.advisor_sessions,
            )

            vlog.global_review_result("global", global_passed, global_feedback[:100])

            # ── 6. 结果评审（即使 global review 不通过，也尽量冻结已通过结果，保证单调增长） ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.RESULT_REVIEW.value)
            all_results = list_result_report_files(results_dir)
            current_fingerprints = calculate_result_fingerprints(results_dir)
            advisors_dicts = [a.model_dump() for a in self.wf.roles.advisors.result_review]
            pending = review_state.get_pending_results(
                all_results,
                advisors_dicts,
                current_fingerprints,
            )
            vlog.result_review_start(cycle, len(all_results), len(pending))

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
            )
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

            await self.recorder.record_review_cycle_summary(
                work_dir=work_dir,
                cycle=cycle,
                global_passed=global_passed,
                global_feedback=global_feedback,
                total_results=len(all_results),
                passed_results=passed_files,
                failed_results=failed_dicts,
                workflow_mode=ctx.review_mode,
                open_blockers=review_state.serialize_open_blockers(
                    limit=review_state.MAX_OPEN_BLOCKERS,
                ),
                plateau_status=plateau_status,
            )

            if not global_passed:
                review_state.record_global_failure(cycle, global_feedback)
            if not result_passed:
                review_state.record_result_failures(failed_items, cycle)
                ctx.failed_result_items = failed_items
            else:
                ctx.failed_result_items = []

            if global_passed and result_passed:
                ctx.plateau_streak = 0
                ctx.plateau_reason = ""
                logger.info("all_reviews_passed", cycle=cycle, mode=ctx.review_mode)
                return None

            if plateau_status.get("abort"):
                error = str(plateau_status.get("reason") or "评审进入停滞状态，提前终止")
                await self.recorder.record_warning(work_dir, error)
                await self.recorder.record_state_change(
                    work_dir,
                    "",
                    AtomicWorkflowState.FAILED.value,
                    detail=error,
                )
                return AtomicWorkflowResult(
                    status="failed",
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
                    open_blockers=len(review_state.get_open_blockers()),
                )
            if not result_passed:
                logger.info(
                    "result_review_failed_retry",
                    cycle=cycle,
                    failed_count=len(failed_items),
                    mode=ctx.review_mode,
                )

        error = f"达到最大评审循环次数 {total_cycle_limit}，仍未通过评审"
        await self.recorder.record_warning(work_dir, error)
        await self.recorder.record_state_change(
            work_dir, "",
            AtomicWorkflowState.FAILED.value,
            detail=error)
        return AtomicWorkflowResult(
            status="failed",
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
    ) -> dict:
        summary_size = 0
        if ctx.summary_file and os.path.isfile(ctx.summary_file):
            try:
                summary_size = os.path.getsize(ctx.summary_file)
            except OSError:
                summary_size = 0

        open_blockers = review_state.serialize_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
        )
        current_failed_files = [item.filename for item in failed_items]
        unreviewed_new_results = [
            name for name in all_results
            if name not in set(passed_files) and name not in set(current_failed_files)
        ]
        historical_removed_result_count = self._count_removed_result_backups(ctx.working_dir)
        return {
            "cycle": cycle,
            "workflow_mode": ctx.review_mode,
            "global_passed": global_passed,
            "global_feedback_preview": (global_feedback or "")[:300],
            "scores": dict(review_state.last_global_scores or {}),
            "open_blocker_count": len(open_blockers),
            "open_blocker_ids": [item.get("id", "") for item in open_blockers],
            "total_results": len(all_results),
            "passed_result_count": len(passed_files),
            "failed_result_count": failed_count,
            "current_failed_result_count": len(current_failed_files),
            "current_failed_result_files": current_failed_files,
            "historical_removed_result_count": historical_removed_result_count,
            "unreviewed_new_result_count": len(unreviewed_new_results),
            "unreviewed_new_result_files": unreviewed_new_results,
            "summary_size": summary_size,
        }

    def _update_plateau_state(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        metrics_history: list[dict],
    ) -> dict:
        if not metrics_history:
            return {
                "stagnant": False,
                "streak": ctx.plateau_streak,
                "workflow_mode": ctx.review_mode,
            }

        current = metrics_history[-1]
        if current["global_passed"] and current["failed_result_count"] == 0:
            ctx.plateau_streak = 0
            ctx.plateau_reason = ""
            return {
                "stagnant": False,
                "streak": 0,
                "workflow_mode": ctx.review_mode,
            }

        if len(metrics_history) < 2:
            return {
                "stagnant": False,
                "streak": ctx.plateau_streak,
                "workflow_mode": ctx.review_mode,
            }

        prev = metrics_history[-2]
        score_gain = self._max_score_gain(prev.get("scores", {}), current.get("scores", {}))
        blocker_not_reduced = current["open_blocker_count"] >= prev["open_blocker_count"]
        blocker_ids_unchanged = (
            bool(current["open_blocker_ids"])
            and current["open_blocker_ids"] == prev.get("open_blocker_ids", [])
        )
        passed_not_grown = current["passed_result_count"] <= prev["passed_result_count"]
        output_not_reduced = (
            current["summary_size"] >= prev["summary_size"]
            and current["total_results"] >= prev["total_results"]
        )
        score_not_improved = score_gain < 0.02

        reasons: list[str] = []
        if blocker_ids_unchanged:
            reasons.append("open blocker IDs 未变化")
        elif blocker_not_reduced:
            reasons.append("open blocker 数量未下降")
        if passed_not_grown:
            reasons.append("已冻结通过结果数量未增长")
        if score_not_improved:
            reasons.append(f"全局评审得分提升不足（max_gain={score_gain:.3f}）")
        if output_not_reduced:
            reasons.append("summary/result 未表现出收缩趋势")

        stagnant = (
            (blocker_ids_unchanged or blocker_not_reduced)
            and passed_not_grown
            and score_not_improved
            and output_not_reduced
        )

        switched_to_closure = False
        abort = False
        if stagnant:
            ctx.plateau_streak += 1
            ctx.plateau_reason = "；".join(reasons) or "评审停滞"
        else:
            ctx.plateau_streak = 0
            ctx.plateau_reason = ""

        if stagnant and ctx.plateau_streak >= 2 and ctx.review_mode != "closure":
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

        if stagnant and ctx.review_mode == "closure" and ctx.plateau_streak >= 3:
            abort = True

        return {
            "stagnant": stagnant,
            "streak": ctx.plateau_streak,
            "workflow_mode": ctx.review_mode,
            "switched_to_closure": switched_to_closure,
            "abort": abort,
            "reason": (
                f"评审在 {ctx.plateau_streak} 个连续 cycle 中停滞，且进入 closure 模式后仍未收敛: {ctx.plateau_reason}"
                if abort else ctx.plateau_reason
            ),
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

    async def _run_end_and_collect(self, ctx):
        vlog.section("🔌", "结束插件链", f"{len(self.wf.end_plugins)} 个插件")
        await self.recorder.record_state_change(
            ctx.working_dir, "", AtomicWorkflowState.END_PLUGINS.value)

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
        await self.recorder.record_state_change(
            ctx.working_dir, "", AtomicWorkflowState.COMPLETED.value)

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
