"""
结果评审执行器 (R6f)

- 遍历 results/ 目录中每个 MD 文件
- 结果间: asyncio 并行（可配置）
- 结果内: 多个参谋智能体串行评审
- 单个结果不通过 → 继续下一结果 (R6g)
- 默认 re_review_on_cycle=False，已通过项不重审
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.models import parse_review_response
from app.pi_vuln_core.review.state import ReviewState, FailedResultItem
from app.pi_vuln_core.utils.file_ops import read_file
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("result_review")


class ResultReviewExecutor:
    """
    结果评审执行器

    并行遍历结果文件，串行调用参谋评审。
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
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        parallel: bool = True,
        concurrency_limit: int = 3,
        advisor_sessions: dict[str, str] | None = None,
    ) -> tuple[bool, list[FailedResultItem]]:
        """
        执行结果评审

        Args:
            concurrency_limit: 结果评审并发上限。仅在 parallel=True 时生效。
            advisor_sessions: 结果评审会话映射。
                              key 使用 "result::<advisor_instance_id>::<result_file>"，
                              这样即使并行评审，也能保证不同结果文件之间会话隔离；
                              当 agent.reset_context=False 时，仅在“同一结果文件跨 cycle”场景复用会话。

        Returns:
            (all_passed: bool, failed_items: list[FailedResultItem])
        """
        if advisor_sessions is None:
            advisor_sessions = {}
        # 列出所有结果文件
        all_result_files = sorted(
            f for f in os.listdir(results_dir)
            if f.endswith(".md") and f != "summary.md"
        ) if os.path.isdir(results_dir) else []

        if not all_result_files:
            logger.info("no_result_files", results_dir=results_dir)
            return True, []

        # 过滤: 跳过已通过的结果 (R6g)
        advisors_dicts = [a.model_dump() for a in advisors_cfg]
        pending = review_state.get_pending_results(
            all_result_files, advisors_dicts)

        if not pending:
            logger.info("all_results_already_passed", cycle=cycle)
            return True, []

        effective_limit = max(1, concurrency_limit)

        logger.info("result_review_start",
                     total=len(all_result_files),
                     pending=len(pending),
                     cycle=cycle,
                     parallel=parallel,
                     concurrency_limit=effective_limit)

        task_content = read_file(task_file)

        # 执行评审（结果间并行，带并发上限；结果内仍串行）
        if parallel and len(pending) > 1 and effective_limit > 1:
            semaphore = asyncio.Semaphore(effective_limit)

            async def _bounded_review(result_file: str):
                async with semaphore:
                    return await self._review_single(
                        advisors_cfg, task_content, results_dir,
                        result_file, work_dir, cycle, review_state,
                        advisor_sessions)

            tasks = [_bounded_review(result_file) for result_file in pending]
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            outcomes = []
            for result_file in pending:
                try:
                    outcome = await self._review_single(
                        advisors_cfg, task_content, results_dir,
                        result_file, work_dir, cycle, review_state,
                        advisor_sessions)
                    outcomes.append(outcome)
                except Exception as e:
                    outcomes.append(e)

        # 汇总
        failed_items: list[FailedResultItem] = []

        for result_file, outcome in zip(pending, outcomes):
            if isinstance(outcome, Exception):
                item = FailedResultItem(
                    filename=result_file, reason=f"评审异常: {outcome}")
                failed_items.append(item)
                review_state.mark_result_failed(
                    result_file, cycle, str(outcome))
            elif not outcome:
                # outcome=False 表示不通过，具体原因已在 _review_single 中记录
                failed_items.append(FailedResultItem(
                    filename=result_file,
                    reason=review_state.result_states.get(
                        result_file, type("", (), {"failure_reason": "未知"})
                    ).failure_reason
                ))
            else:
                review_state.mark_result_passed(result_file, cycle)

        all_passed = len(failed_items) == 0

        logger.info("result_review_done",
                     cycle=cycle,
                     total_pending=len(pending),
                     passed=len(pending) - len(failed_items),
                     failed=len(failed_items))

        return all_passed, failed_items

    async def _review_single(
        self,
        advisors_cfg: list[AdvisorInstanceDef],
        task_content: str,
        results_dir: str,
        result_file: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        advisor_sessions: dict[str, str] | None = None,
    ) -> bool:
        """
        评审单个结果文件 (R6f: 结果内串行)

        Returns: True=通过, False=不通过
        """
        if advisor_sessions is None:
            advisor_sessions = {}

        result_path = os.path.join(results_dir, result_file)
        result_content = read_file(result_path)

        for advisor_def in advisors_cfg:
            # 检查该 advisor 是否需要重审已通过项
            if (cycle > 1
                    and not advisor_def.re_review_on_cycle
                    and review_state.is_result_passed(result_file)):
                continue

            agent = self.agents.get(advisor_def.agent_id)

            # 构建 prompt (R7)
            system_prompt = read_file(advisor_def.system_prompt_file)
            user_prompt_tpl = read_file(advisor_def.user_prompt_template)
            user_prompt = render_string(
                user_prompt_tpl,
                task=task_content,
                result=result_content,
                result_filename=result_file,
                cycle=str(cycle),
            )

            # 会话管理（结果评审必须按“结果文件”隔离会话）
            # reset_context=True  → 每次新建 session (独立客观)
            # reset_context=False → 仅复用同一 result_file 的历史 session，
            #                       避免不同结果文件之间相互污染，也避免并发复用同一 session
            session_key = f"result::{advisor_def.instance_id}::{result_file}"
            session_id = advisor_sessions.get(session_key)
            should_reset = agent.should_reset_context()

            if should_reset or session_id is None:
                session_id = await agent.create_session()
                advisor_sessions[session_key] = session_id

            response = await agent.send_message(
                message=user_prompt,
                system_prompt=system_prompt,
                session_id=session_id,
                working_dir=work_dir,
            )

            if not response.success:
                reason = f"Agent错误: {response.error}"
                await self.recorder.record_result_review(
                    work_dir=work_dir,
                    result_file=result_file,
                    advisor_id=advisor_def.instance_id,
                    cycle=cycle, passed=False, content=reason,
                    agent_id=advisor_def.agent_id,
                    role_name=advisor_def.role_name,
                    raw_content=response.content if response.content else "",
                    verdict="ERROR",
                    detail_feedback=reason)
                review_state.mark_result_failed(result_file, cycle, reason)
                return False

            parsed = parse_review_response(response.content)

            # 记录 (R6h)
            await self.recorder.record_result_review(
                work_dir=work_dir,
                result_file=result_file,
                advisor_id=advisor_def.instance_id,
                cycle=cycle,
                passed=parsed.passed,
                content=parsed.feedback,
                agent_id=advisor_def.agent_id,
                role_name=advisor_def.role_name,
                scores=parsed.scores,
                confidence=parsed.confidence,
                raw_content=parsed.raw_content,
                verdict=parsed.verdict,
                detail_feedback=parsed.feedback_detail)

            if not parsed.passed:
                # 当前结果不通过 → 放弃继续评审 (R6g)
                review_state.mark_result_failed(
                    result_file, cycle, parsed.feedback_detail or parsed.feedback)
                logger.info("result_review_failed",
                             result_file=result_file,
                             advisor=advisor_def.instance_id,
                             cycle=cycle)
                return False

        return True
