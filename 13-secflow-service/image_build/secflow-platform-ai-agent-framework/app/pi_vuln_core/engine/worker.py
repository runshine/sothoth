"""
Worker 执行器

负责原子工作流中的：
- Worker 执行阶段 (R6c)
- 自我反思阶段 (R6d)
- 总结阶段 (R6e)
"""

from __future__ import annotations

import os
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.file_ops import read_file
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("worker_executor")


class WorkerExecutor:
    """Worker 执行器"""

    def __init__(
        self,
        agent_registry: AgentRuntimeRegistry,
        recorder: ExecutionRecorder,
    ):
        self.agents = agent_registry
        self.recorder = recorder

    async def execute_worker(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> None:
        """
        Worker 阶段 (R6c)

        调用 worker 智能体执行任务，直到完成。
        如果非首轮，prompt 中包含评审失败反馈。
        """
        worker_cfg = wf_def.roles.worker
        agent = self.agents.get(worker_cfg.agent_id)

        # 决定是否新建会话 (R12)
        if worker_cfg.new_session or ctx.cycle == 1:
            session_id = await agent.create_session()
            ctx.worker_session_id = session_id
        else:
            session_id = ctx.worker_session_id
            if session_id is None:
                session_id = await agent.create_session()
                ctx.worker_session_id = session_id

        # 构建 prompt
        system_prompt = read_file(worker_cfg.prompts.work.system_prompt_file)
        user_prompt = self._build_user_prompt(wf_def, ctx, review_state)

        max_turns = wf_def.engine.max_worker_turns_per_cycle

        logger.info("worker_execute_start",
                     workflow_id=ctx.workflow_id,
                     task_id=ctx.task_id,
                     cycle=ctx.cycle,
                     session_id=session_id)

        # 多轮执行
        response = await agent.multi_turn_execute(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            working_dir=ctx.working_dir,
            max_turns=max_turns,
            session_id=session_id,
        )

        if not response.success:
            logger.error("worker_execute_error",
                         error=response.error,
                         workflow_id=ctx.workflow_id)

        logger.info("worker_execute_done",
                     workflow_id=ctx.workflow_id,
                     turns=response.turn_count,
                     finished=response.finished)

    def _build_user_prompt(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        """构建 Worker 的 user prompt"""
        # 读取任务描述
        task_content = read_file(ctx.task_file)

        # 读取 user prompt 模板
        base_prompt = read_file(wf_def.roles.worker.prompts.work.user_prompt_file)

        # 渲染变量
        user_prompt = render_string(
            base_prompt,
            task=task_content,
            task_file=ctx.task_file,
            working_dir=ctx.working_dir,
            cycle=str(ctx.cycle),
        )

        # 如果非首轮 + 有评审失败反馈 → 注入 (R6g)
        if ctx.cycle > 1 and review_state.has_failures():
            feedback = review_state.format_failure_feedback()
            user_prompt += f"\n\n## 上轮评审反馈（请针对性修改）\n\n{feedback}"

            # 如果有失败的结果项，列出具体信息
            failed = review_state.get_failed_result_filenames()
            if failed:
                user_prompt += (
                    f"\n\n## 需要修正的结果项\n\n"
                    + "\n".join(f"- {f}" for f in failed)
                )

        return user_prompt

    async def execute_reflection(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
    ) -> None:
        """
        自我反思阶段 (R6d)

        按序执行反思 prompt，每一轮等待上一轮完成。
        """
        worker_cfg = wf_def.roles.worker
        reflection_prompts = worker_cfg.prompts.reflection

        if not reflection_prompts:
            logger.debug("no_reflection_prompts", workflow_id=ctx.workflow_id)
            return

        agent = self.agents.get(worker_cfg.agent_id)

        for i, reflect_cfg in enumerate(reflection_prompts):
            prompt = read_file(reflect_cfg.prompt_file)
            prompt = render_string(
                prompt,
                working_dir=ctx.working_dir,
                cycle=str(ctx.cycle),
            )

            logger.info("reflection_start",
                         round=i + 1,
                         prompt_id=reflect_cfg.id,
                         workflow_id=ctx.workflow_id)

            # 每一轮必须等上一轮结束 (R6d: 串行)
            response = await agent.send_message(
                message=prompt,
                session_id=ctx.worker_session_id,
                working_dir=ctx.working_dir,
            )

            await self.recorder.record_reflection(
                work_dir=ctx.working_dir,
                round_num=i + 1,
                prompt_id=reflect_cfg.id,
                response=response.content,
            )

            logger.info("reflection_done",
                         round=i + 1, prompt_id=reflect_cfg.id)

    async def execute_summary(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
    ) -> tuple[str, str]:
        """
        总结阶段 (R6e)

        输出 summary.md + results/ 目录

        Returns:
            (summary_path, results_dir)
        """
        worker_cfg = wf_def.roles.worker
        summary_cfg = worker_cfg.prompts.summary
        agent = self.agents.get(worker_cfg.agent_id)

        summary_path = os.path.join(
            ctx.working_dir, summary_cfg.output_summary_filename)
        results_dir = os.path.join(
            ctx.working_dir, summary_cfg.output_results_dir)

        # 确保目录存在
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        os.makedirs(results_dir, exist_ok=True)

        prompt = read_file(summary_cfg.prompt_file)
        prompt = render_string(
            prompt,
            working_dir=ctx.working_dir,
            summary_path=summary_path,
            results_dir=results_dir,
            cycle=str(ctx.cycle),
        )

        logger.info("summary_start", workflow_id=ctx.workflow_id)

        response = await agent.send_message(
            message=prompt,
            session_id=ctx.worker_session_id,
            working_dir=ctx.working_dir,
        )

        logger.info("summary_done",
                     workflow_id=ctx.workflow_id,
                     summary_path=summary_path,
                     results_dir=results_dir)

        return summary_path, results_dir
