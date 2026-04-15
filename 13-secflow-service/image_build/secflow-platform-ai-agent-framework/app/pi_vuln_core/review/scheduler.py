"""
评审调度器

整合全局评审 + 结果评审，提供统一调用入口
"""

from __future__ import annotations

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorsDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.result_review import ResultReviewExecutor
from app.pi_vuln_core.review.state import ReviewState, FailedResultItem
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("review_scheduler")


class ReviewScheduler:
    """
    评审调度器

    统一管理全局评审和结果评审的调用流程
    """

    def __init__(
        self,
        agent_registry: AgentRuntimeRegistry,
        recorder: ExecutionRecorder,
    ):
        self.global_executor = GlobalReviewExecutor(agent_registry, recorder)
        self.result_executor = ResultReviewExecutor(agent_registry, recorder)

    async def run_global_review(
        self,
        advisors_def: AdvisorsDef,
        task_file: str,
        summary_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        advisor_sessions: dict[str, str],
    ) -> tuple[bool, str]:
        """执行全局评审"""
        if not advisors_def.global_review:
            logger.info("no_global_reviewers", skip=True)
            return True, ""

        return await self.global_executor.execute(
            advisors_cfg=advisors_def.global_review,
            task_file=task_file,
            summary_file=summary_file,
            results_dir=results_dir,
            work_dir=work_dir,
            cycle=cycle,
            review_state=review_state,
            advisor_sessions=advisor_sessions,
        )

    async def run_result_review(
        self,
        advisors_def: AdvisorsDef,
        task_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        parallel: bool = True,
        concurrency_limit: int = 3,
        advisor_sessions: dict[str, str] | None = None,
    ) -> tuple[bool, list[FailedResultItem]]:
        """执行结果评审"""
        if not advisors_def.result_review:
            logger.info("no_result_reviewers", skip=True)
            return True, []

        if advisor_sessions is None:
            advisor_sessions = {}

        return await self.result_executor.execute(
            advisors_cfg=advisors_def.result_review,
            task_file=task_file,
            results_dir=results_dir,
            work_dir=work_dir,
            cycle=cycle,
            review_state=review_state,
            parallel=parallel,
            concurrency_limit=concurrency_limit,
            advisor_sessions=advisor_sessions,
        )
