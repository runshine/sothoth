"""
全局评审执行器 (R6f)

- 评审对象: 原始任务 + 总结报告 + 结果清单
- 多个全局评审参谋智能体 **串行** 执行
- 任何一个不通过 → 整体不通过 → 回到 Worker (R6g)
- 默认 re_review_on_cycle=True
"""

from __future__ import annotations

import os
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.models import parse_review_response
from app.pi_vuln_core.review.state import ReviewState, GlobalReviewRecord
from app.pi_vuln_core.utils.file_ops import read_file, list_dir_files
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("global_review")


class GlobalReviewExecutor:
    """
    全局评审执行器

    串行调用每个全局评审参谋，任一不通过则整体不通过。
    """

    def __init__(
        self,
        agent_registry: AgentRuntimeRegistry,
        recorder: ExecutionRecorder,
    ):
        self.agents = agent_registry
        self.recorder = recorder

    async def execute(
        self,
        advisors_cfg: list[AdvisorInstanceDef],
        task_file: str,
        summary_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        advisor_sessions: dict[str, str],
    ) -> tuple[bool, str]:
        """
        执行全局评审

        Args:
            advisors_cfg:     全局评审参谋列表
            task_file:        原始任务文件路径
            summary_file:     总结报告路径
            results_dir:      结果文件夹路径
            work_dir:         工作目录
            cycle:            当前循环轮次
            review_state:     评审状态追踪器
            advisor_sessions: advisor_id → session_id 映射

        Returns:
            (passed: bool, feedback: str)
        """
        task_content = read_file(task_file)
        if summary_file and os.path.isfile(summary_file):
            summary_content = read_file(summary_file)
        else:
            summary_content = "(Worker 未生成 summary.md)"
        results_list = list_dir_files(results_dir, suffix=".md")
        results_content = "\n".join(
            f"- {f}" for f in results_list
        ) if results_list else "(无结果文件)"

        for advisor_def in advisors_cfg:
            # 检查是否需要本轮评审
            if cycle > 1 and not advisor_def.re_review_on_cycle:
                logger.debug("skip_global_review",
                             advisor=advisor_def.instance_id,
                             reason="re_review_on_cycle=False")
                continue

            agent = self.agents.get(advisor_def.agent_id)

            # 构建 prompt (R7)
            system_prompt = read_file(advisor_def.system_prompt_file)
            user_prompt_tpl = read_file(advisor_def.user_prompt_template)
            user_prompt = render_string(
                user_prompt_tpl,
                task=task_content,
                summary=summary_content,
                results=results_content,
                results_list="\n".join(results_list),
                cycle=str(cycle),
            )

            # 会话管理
            session_id = advisor_sessions.get(advisor_def.instance_id)
            should_reset = agent.should_reset_context()

            if should_reset or session_id is None:
                session_id = await agent.create_session()
                advisor_sessions[advisor_def.instance_id] = session_id

            # 调用评审
            logger.info("global_review_start",
                         advisor=advisor_def.instance_id,
                         cycle=cycle)

            response = await agent.send_message(
                message=user_prompt,
                system_prompt=system_prompt,
                session_id=session_id,
                working_dir=work_dir,
            )

            if not response.success:
                logger.error("global_review_agent_error",
                             advisor=advisor_def.instance_id,
                             error=response.error)
                # Agent 错误视为不通过
                feedback = f"评审智能体错误: {response.error}"
                await self._record(
                    work_dir, advisor_def, cycle, False, feedback,
                    raw_content=response.content if response.content else "",
                    verdict="ERROR",
                    detail_feedback=feedback,
                )
                review_state.global_review_history.append(
                    GlobalReviewRecord(cycle=cycle,
                                       advisor_id=advisor_def.instance_id,
                                       passed=False, feedback=feedback))
                return False, feedback

            # 解析评审结果
            parsed = parse_review_response(response.content)

            # 记录 (R6h)
            await self._record(
                work_dir, advisor_def, cycle,
                parsed.passed, parsed.feedback,
                parsed.scores, parsed.confidence, parsed.raw_content,
                parsed.verdict, parsed.feedback_detail)

            review_state.global_review_history.append(
                GlobalReviewRecord(
                    cycle=cycle,
                    advisor_id=advisor_def.instance_id,
                    passed=parsed.passed,
                    feedback=parsed.feedback_detail or parsed.feedback))

            logger.info("global_review_result",
                         advisor=advisor_def.instance_id,
                         cycle=cycle,
                         passed=parsed.passed)

            # 任何一个不通过 → 立即返回 (R6g)
            if not parsed.passed:
                return False, (parsed.feedback_detail or parsed.feedback)

        return True, ""

    async def _record(
        self,
        work_dir: str,
        advisor_def: AdvisorInstanceDef,
        cycle: int,
        passed: bool,
        feedback: str,
        scores: dict | None = None,
        confidence: float | None = None,
        raw_content: str = "",
        verdict: str = "",
        detail_feedback: str = "",
    ) -> None:
        await self.recorder.record_global_review(
            work_dir=work_dir,
            advisor_id=advisor_def.instance_id,
            cycle=cycle,
            passed=passed,
            content=feedback,
            agent_id=advisor_def.agent_id,
            role_name=advisor_def.role_name,
            scores=scores,
            confidence=confidence,
            raw_content=raw_content,
            verdict=verdict,
            detail_feedback=detail_feedback,
        )
