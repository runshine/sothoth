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
from app.pi_vuln_core.observer import ExecutionObserver, NullExecutionObserver
from app.pi_vuln_core.engine.worker import WorkerExecutor
from app.pi_vuln_core.plugins.base import PluginContext
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.scheduler import ReviewScheduler
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.workspace.manager import WorkspaceManager
from app.pi_vuln_core.utils.file_ops import read_json, copy_file, list_dir_files
from app.pi_vuln_core.utils.logger import get_logger
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
        observer: ExecutionObserver | None = None,
    ):
        self.wf = wf_def
        self.agents = agent_registry
        self.plugin_exec = plugin_executor
        self.workspace = workspace
        self.recorder = recorder
        self.global_cfg = global_config
        self.observer = observer or NullExecutionObserver()

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
                await self.observer.on_workflow_restart(
                    workflow_id=self.wf.id,
                    task_id=task_id,
                    working_dir=work_dir,
                    attempt=attempt,
                )
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
        if not result.success and result.error:
            await self.observer.on_workflow_abnormal_exit(
                workflow_id=self.wf.id,
                task_id=task_id,
                working_dir=work_dir,
                error=result.error,
            )

        if result.success:
            vlog.workflow_completed(result.cycles_used, len(result.next_tasks))
        else:
            vlog.workflow_failed(result.error or "unknown")

        logger.info("atomic_workflow_done",
                     workflow_id=self.wf.id, status=result.status,
                     cycles=result.cycles_used,
                     next_tasks=len(result.next_tasks))
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
        await self.observer.check_cancel(
            "atomic:start_plugins",
            workflow_id=self.wf.id,
            task_id=task_id,
            working_dir=work_dir,
        )

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

        for cycle in range(1, self.max_cycles + 1):
            ctx.cycle = cycle
            await self.observer.check_cancel(
                "atomic:cycle_start",
                workflow_id=self.wf.id,
                task_id=task_id,
                working_dir=work_dir,
                cycle=cycle,
            )
            await self.observer.on_cycle_started(
                workflow_id=self.wf.id,
                task_id=task_id,
                working_dir=work_dir,
                cycle=cycle,
            )
            vlog.cycle_start(cycle, self.max_cycles)

            # ── 2. Worker 执行 ──
            vlog.worker_start(cycle)
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.WORKER.value,
                detail=f"cycle={cycle}")
            await self.worker_exec.execute_worker(self.wf, ctx, review_state)
            vlog.worker_done(1)

            # ── 3. 自我反思 ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.REFLECT.value)
            for i, r in enumerate(self.wf.roles.worker.prompts.reflection):
                vlog.reflection_start(i + 1, r.id)
            await self.worker_exec.execute_reflection(self.wf, ctx)
            if self.wf.roles.worker.prompts.reflection:
                vlog.reflection_done(len(self.wf.roles.worker.prompts.reflection))

            # ── 4. 总结 ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.SUMMARY.value)
            summary_path, results_dir = \
                await self.worker_exec.execute_summary(self.wf, ctx)
            ctx.summary_file = summary_path
            ctx.results_dir = results_dir
            result_files = list_dir_files(results_dir, suffix=".md")
            vlog.summary_done(summary_path, len(result_files))
            await self.recorder.snapshot_summary(work_dir, cycle, "after_summary")
            await self.observer.on_summary_completed(
                workflow_id=self.wf.id,
                task_id=task_id,
                working_dir=work_dir,
                cycle=cycle,
                summary_file=summary_path,
                results_dir=results_dir,
                result_count=len(result_files),
            )

            # ── 5. 全局评审 ──
            global_advisors = self.wf.roles.advisors.global_review
            vlog.global_review_start(cycle, len(global_advisors))
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.GLOBAL_REVIEW.value)

            global_passed, global_feedback = \
                await self.review_sched.run_global_review(
                    advisors_def=self.wf.roles.advisors,
                    task_file=ctx.task_file,
                    summary_file=ctx.summary_file,
                    results_dir=ctx.results_dir,
                    work_dir=work_dir, cycle=cycle,
                    review_state=review_state,
                    advisor_sessions=ctx.advisor_sessions)

            vlog.global_review_result("global", global_passed,
                                       global_feedback[:100])

            if not global_passed:
                review_state.record_global_failure(cycle, global_feedback)
                await self.recorder.record_review_cycle_summary(
                    work_dir=work_dir, cycle=cycle,
                    global_passed=False, global_feedback=global_feedback,
                    total_results=len(list_dir_files(results_dir, suffix=".md")),
                    passed_results=[], failed_results=[])
                logger.info("global_review_failed_retry",
                             cycle=cycle, feedback=global_feedback[:200])
                await self.observer.on_cycle_completed(
                    workflow_id=self.wf.id,
                    task_id=task_id,
                    working_dir=work_dir,
                    cycle=cycle,
                    outcome="global_review_failed",
                )
                continue

            # ── 6. 结果评审 ──
            await self.recorder.record_state_change(
                work_dir, "", AtomicWorkflowState.RESULT_REVIEW.value)
            all_results = list_dir_files(results_dir, suffix=".md")
            advisors_dicts = [a.model_dump() for a in
                              self.wf.roles.advisors.result_review]
            pending = review_state.get_pending_results(
                all_results, advisors_dicts)
            vlog.result_review_start(cycle, len(all_results), len(pending))

            result_passed, failed_items = \
                await self.review_sched.run_result_review(
                    advisors_def=self.wf.roles.advisors,
                    task_file=ctx.task_file,
                    results_dir=ctx.results_dir,
                    work_dir=work_dir, cycle=cycle,
                    review_state=review_state,
                    parallel=self.global_cfg.parallel_result_review,
                    advisor_sessions=ctx.advisor_sessions)

            # 打印每个结果的评审情况
            for f in all_results:
                if review_state.is_result_passed(f):
                    vlog.result_review_item(f, True)
                else:
                    state = review_state.result_states.get(f)
                    reason = state.failure_reason[:80] if state else ""
                    vlog.result_review_item(f, False, reason)

            passed_count = len([f for f in all_results
                                if review_state.is_result_passed(f)])
            failed_count = len(all_results) - passed_count
            vlog.result_review_summary(passed_count, failed_count)

            # 记录本轮评审汇总 + summary 快照
            passed_files = [f for f in all_results if review_state.is_result_passed(f)]
            failed_dicts = ([{"filename": fi.filename, "reason": fi.reason}
                             for fi in failed_items] if not result_passed else [])
            await self.recorder.record_review_cycle_summary(
                work_dir=work_dir, cycle=cycle,
                global_passed=True, global_feedback=global_feedback,
                total_results=len(all_results),
                passed_results=passed_files, failed_results=failed_dicts)
            await self.recorder.snapshot_summary(work_dir, cycle, "after_review")

            if not result_passed:
                review_state.record_result_failures(failed_items, cycle)
                ctx.failed_result_items = failed_items
                logger.info("result_review_failed_retry",
                             cycle=cycle, failed_count=len(failed_items))
                await self.observer.on_cycle_completed(
                    workflow_id=self.wf.id,
                    task_id=task_id,
                    working_dir=work_dir,
                    cycle=cycle,
                    outcome="result_review_failed",
                    failed_count=len(failed_items),
                )
                continue

            logger.info("all_reviews_passed", cycle=cycle)
            await self.observer.on_cycle_completed(
                workflow_id=self.wf.id,
                task_id=task_id,
                working_dir=work_dir,
                cycle=cycle,
                outcome="passed",
            )
            break
        else:
            await self.recorder.record_warning(
                work_dir, f"达到最大评审循环次数 {self.max_cycles}，强制结束")

        result = await self._run_end_and_collect(ctx)
        result.cycles_used = ctx.cycle
        return result

    async def _run_end_and_collect(self, ctx):
        vlog.section("🔌", "结束插件链", f"{len(self.wf.end_plugins)} 个插件")
        await self.recorder.record_state_change(
            ctx.working_dir, "", AtomicWorkflowState.END_PLUGINS.value)
        await self.observer.check_cancel(
            "atomic:end_plugins",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            working_dir=ctx.working_dir,
            cycle=ctx.cycle,
        )

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
            plugin_ids,
            base_ctx,
            phase,
            recorder=self.recorder,
            cancel_check=self.observer.check_cancel,
        )
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
