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
import contextlib
import os
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.engine.checkpoint import record_step_checkpoint
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.models import ParsedReviewResult
from app.pi_vuln_core.review.advisor_runtime_retry import (
    append_retry_summary,
    is_retryable_review_runtime_error,
    retry_session_hint,
    review_runtime_retry_limit,
)
from app.pi_vuln_core.review.result_review_parser import (
    ResultReviewParseOutcome,
    parse_result_review_response,
)
from app.pi_vuln_core.review.read_only_guard import (
    diff_read_only_snapshots,
    format_read_only_violations,
    take_read_only_snapshot,
)
from app.pi_vuln_core.review.state import (
    ReviewState,
    FailedResultItem,
    calculate_result_fingerprints,
)
from app.pi_vuln_core.utils.file_ops import read_file, read_json
from app.pi_vuln_core.utils.result_docs import (
    infer_result_lifecycle,
    list_result_report_files,
    list_supporting_markdown_files,
)
from app.pi_vuln_core.utils.vulnerability_list import apply_result_review_verdict
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("result_review")

_RESULT_REVIEW_SCHEMA_REPAIR_LIMIT = 2


class ResultReviewFrameworkError(RuntimeError):
    """Raised when result review cannot produce a business verdict safely."""

    def __init__(
        self,
        *,
        result_file: str,
        advisor_id: str,
        reason: str,
        error_code: str = "",
    ) -> None:
        self.result_file = result_file
        self.advisor_id = advisor_id
        self.reason = reason
        self.error_code = error_code
        prefix = f"[{error_code}] " if error_code else ""
        super().__init__(
            f"{prefix}{result_file} / {advisor_id}: {reason}"
        )


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
        resume_cursor: dict | None = None,
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
        all_result_files = list_result_report_files(results_dir) if os.path.isdir(results_dir) else []

        if not all_result_files:
            logger.info("no_result_files", results_dir=results_dir)
            return True, []

        current_fingerprints = calculate_result_fingerprints(results_dir)
        all_result_files = self._filter_active_result_files(
            all_result_files=all_result_files,
            results_dir=results_dir,
            cycle=cycle,
            review_state=review_state,
            current_fingerprints=current_fingerprints,
        )
        if not all_result_files:
            logger.info("no_active_result_files", results_dir=results_dir)
            return True, []

        # 过滤: 跳过已评审且文件内容未变化的结果 (R6g)
        advisors_dicts = [a.model_dump() for a in advisors_cfg]
        pending = review_state.get_pending_results(
            all_result_files, advisors_dicts, current_fingerprints)
        incomplete_current_cycle = self._results_with_incomplete_current_cycle(
            advisors_cfg=advisors_cfg,
            work_dir=work_dir,
            cycle=cycle,
            result_files=all_result_files,
        )
        current_cycle_framework_failed = {
            name
            for name, state in review_state.result_states.items()
            if name in set(all_result_files)
            and state.active
            and not state.passed
            and state.last_reviewed_cycle == cycle
            and state.failure_reason
        }
        if current_cycle_framework_failed:
            incomplete_current_cycle = [
                name for name in incomplete_current_cycle
                if name not in current_cycle_framework_failed
            ]
        if incomplete_current_cycle:
            pending = sorted(set(pending) | set(incomplete_current_cycle))
            logger.info(
                "result_review_resume_pending_incomplete_nodes",
                cycle=cycle,
                files=incomplete_current_cycle,
                resume_cursor=resume_cursor or {},
            )
        carried_failed_items = [
            FailedResultItem(
                filename=name,
                reason=review_state.result_states[name].failure_reason,
                cycle=review_state.result_states[name].last_reviewed_cycle,
            )
            for name in sorted(current_cycle_framework_failed)
            if review_state.is_result_failed(
                name,
                current_fingerprints.get(name, ""),
            )
        ]

        if not pending:
            if carried_failed_items:
                logger.info(
                    "result_review_skip_unchanged_failed",
                    cycle=cycle,
                    count=len(carried_failed_items),
                    files=[item.filename for item in carried_failed_items],
                )
                return False, carried_failed_items

            logger.info("all_results_already_reviewed", cycle=cycle)
            return True, []

        effective_limit = max(1, concurrency_limit)

        logger.info("result_review_start",
                     total=len(all_result_files),
                     pending=len(pending),
                     cycle=cycle,
                     parallel=parallel,
                     concurrency_limit=effective_limit)

        # 执行评审（结果间并行，带并发上限；结果内仍串行）
        if parallel and len(pending) > 1 and effective_limit > 1:
            semaphore = asyncio.Semaphore(effective_limit)

            async def _bounded_review(result_file: str):
                async with semaphore:
                    return await self._review_single(
                        advisors_cfg,
                        task_file,
                        results_dir,
                        result_file,
                        work_dir,
                        cycle,
                        review_state,
                        advisor_sessions,
                        current_fingerprints.get(result_file),
                    )

            tasks = [_bounded_review(result_file) for result_file in pending]
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            outcomes = []
            for result_file in pending:
                try:
                    outcome = await self._review_single(
                        advisors_cfg,
                        task_file,
                        results_dir,
                        result_file,
                        work_dir,
                        cycle,
                        review_state,
                        advisor_sessions,
                        current_fingerprints.get(result_file),
                    )
                    outcomes.append(outcome)
                except Exception as e:
                    outcomes.append(e)

        # 汇总
        failed_items: list[FailedResultItem] = list(carried_failed_items)

        for result_file, outcome in zip(pending, outcomes):
            current_fingerprint = current_fingerprints.get(result_file, "")
            if isinstance(outcome, ResultReviewFrameworkError):
                raise outcome
            if isinstance(outcome, Exception):
                raise ResultReviewFrameworkError(
                    result_file=result_file,
                    advisor_id="result_review",
                    reason=f"结果评审框架异常：{outcome}",
                ) from outcome
            elif not outcome:
                state = review_state.result_states.get(result_file)
                if state is not None and review_state.is_result_failed(result_file, current_fingerprint):
                    failed_items.append(FailedResultItem(
                        filename=result_file,
                        reason=state.failure_reason or state.review_feedback or "结果评审未通过",
                        cycle=cycle,
                    ))
            else:
                # _review_single has already persisted business verdicts into
                # ReviewState and vulnerability_list.json. Do not convert
                # FALSE_POSITIVE into Worker repair items.
                continue

        # Parallel result reviews may update vulnerability_list.json concurrently.
        # Re-apply the in-memory states serially so the final list contains all
        # reviewed results from this cycle.
        for result_file in all_result_files:
            state = review_state.result_states.get(result_file)
            if state is None or state.last_reviewed_cycle != cycle:
                continue
            verdict = str(state.verdict or "").strip().upper()
            if verdict not in {"CONFIRMED", "FALSE_POSITIVE"}:
                continue
            apply_result_review_verdict(
                working_dir=work_dir,
                results_dir=results_dir,
                result_file=result_file,
                verdict=verdict,
                passed=(verdict == "CONFIRMED"),
                confidence=state.confidence,
                feedback=state.review_feedback or state.failure_reason,
                cycle=cycle,
                fingerprint=current_fingerprints.get(result_file, ""),
            )

        all_passed = len(failed_items) == 0

        logger.info("result_review_done",
                     cycle=cycle,
                     total_pending=len(pending),
                     passed=len(pending) - len(failed_items),
                     failed=len(failed_items))

        return all_passed, failed_items

    @staticmethod
    def _filter_active_result_files(
        *,
        all_result_files: list[str],
        results_dir: str,
        cycle: int,
        review_state: ReviewState,
        current_fingerprints: dict[str, str],
    ) -> list[str]:
        """Exclude withdrawn/false-positive/superseded result files from future FP repair loops."""
        active_files: list[str] = []
        inactive_files: list[str] = []
        for result_file in all_result_files:
            result_path = Path(results_dir) / result_file
            lifecycle = infer_result_lifecycle(result_path)
            if bool(lifecycle.get("active", True)):
                active_files.append(result_file)
                continue
            existing_state = review_state.result_states.get(result_file)
            if existing_state is None or existing_state.passed:
                active_files.append(result_file)
                continue
            status = str(lifecycle.get("status") or "inactive")
            review_state.mark_result_inactive(
                result_file,
                cycle,
                lifecycle_status=status,
                reason=f"result lifecycle marked {status}; skip repeated result repair",
                fingerprint=current_fingerprints.get(result_file, ""),
            )
            inactive_files.append(result_file)

        if inactive_files:
            logger.info(
                "result_review_skip_inactive_results",
                cycle=cycle,
                files=inactive_files,
            )
        return active_files

    def _results_with_incomplete_current_cycle(
        self,
        *,
        advisors_cfg: list[AdvisorInstanceDef],
        work_dir: str,
        cycle: int,
        result_files: list[str],
    ) -> list[str]:
        """Find result files whose current-cycle advisor nodes are partial."""
        incomplete: list[str] = []
        for result_file in result_files:
            cycle_dir = (
                Path(work_dir)
                / "reviews"
                / "results"
                / Path(result_file).stem
                / f"cycle_{cycle:03d}"
            )
            if not cycle_dir.is_dir():
                continue
            for advisor_def in advisors_cfg:
                existing = self._load_existing_result_review_record(
                    work_dir=work_dir,
                    cycle=cycle,
                    advisor_def=advisor_def,
                    result_file=result_file,
                )
                if existing is None:
                    incomplete.append(result_file)
                    break
                if not bool(existing.get("passed", False)):
                    break
        return sorted(set(incomplete))

    @staticmethod
    def _build_result_review_session_hint(
        *,
        advisor_def: AdvisorInstanceDef,
        cycle: int,
        result_file: str,
    ) -> str:
        return (
            f"result_review_cycle_{cycle:03d}_"
            f"{Path(result_file).stem}_{advisor_def.instance_id}"
        )

    def _build_result_review_context_text(
        self,
        *,
        task_file: str,
        result_path: str,
        result_file: str,
        work_dir: str,
    ) -> dict[str, str]:
        supporting_docs_dir = Path(work_dir) / "supporting_docs"
        vulnerability_list_file = Path(work_dir) / "_meta" / "vulnerability_list.json"
        supporting_docs = list_supporting_markdown_files(supporting_docs_dir)
        lines = [
            "## 当前待验证对象",
            f"- 任务文件: `{task_file}`",
            f"- 待验证报告: `{result_path}`",
            f"- 辅助文档目录: `{supporting_docs_dir}`",
            f"- 漏洞状态列表（只读，最终 verdict 由框架写回）: `{vulnerability_list_file}`",
            "",
            "## 开始前必须读取",
            f"- `{task_file}`",
            f"- `{result_path}`",
        ]
        if supporting_docs:
            lines.extend([
                "",
                "## 可按需读取的 supporting docs",
                *[f"- `{supporting_docs_dir / name}`" for name in supporting_docs],
            ])
        return {
            "supporting_docs_dir": str(supporting_docs_dir),
            "optional_supporting_docs": ", ".join(supporting_docs) if supporting_docs else "(无)",
            "context_text": "\n".join(lines),
            "repair_hint": f"task=`{task_file}`, result=`{result_path}`, supporting_docs_dir=`{supporting_docs_dir}`",
        }

    @staticmethod
    def _load_existing_result_review_record(
        *,
        work_dir: str,
        cycle: int,
        advisor_def: AdvisorInstanceDef,
        result_file: str,
    ) -> dict | None:
        record_path = (
            Path(work_dir)
            / "reviews"
            / "results"
            / Path(result_file).stem
            / f"cycle_{cycle:03d}"
            / f"{advisor_def.instance_id}.json"
        )
        if not record_path.is_file():
            return None
        try:
            data = read_json(record_path)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        parser_mode = str(data.get("parser_mode") or "").strip()
        verdict = str(data.get("verdict") or "").strip()
        if parser_mode == "agent_error" or verdict == "ERROR":
            return None
        verdict_upper = verdict.upper()
        passed = bool(data.get("passed", False))
        if verdict_upper not in {"CONFIRMED", "FALSE_POSITIVE"}:
            return None
        if passed and verdict_upper != "CONFIRMED":
            return None
        if not passed and verdict_upper != "FALSE_POSITIVE":
            return None
        return data

    async def _review_single(
        self,
        advisors_cfg: list[AdvisorInstanceDef],
        task_file: str,
        results_dir: str,
        result_file: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        advisor_sessions: dict[str, str] | None = None,
        current_fingerprint: str | None = None,
    ) -> bool:
        """
        评审单个结果文件 (R6f: 结果内串行)

        Returns: True=通过, False=不通过
        """
        if advisor_sessions is None:
            advisor_sessions = {}

        result_path = os.path.join(results_dir, result_file)
        review_context = self._build_result_review_context_text(
            task_file=task_file,
            result_path=result_path,
            result_file=result_file,
            work_dir=work_dir,
        )

        for advisor_def in advisors_cfg:
            # 检查该 advisor 是否需要重审已通过项
            if (cycle > 1
                    and not advisor_def.re_review_on_cycle
                    and review_state.is_result_passed(
                        result_file, current_fingerprint)):
                continue

            existing_record = self._load_existing_result_review_record(
                work_dir=work_dir,
                cycle=cycle,
                advisor_def=advisor_def,
                result_file=result_file,
            )
            if existing_record is not None:
                reason = str(
                    existing_record.get("feedback_detail")
                    or existing_record.get("feedback")
                    or "结果评审未通过"
                )
                verdict = str(existing_record.get("verdict") or "").strip().upper()
                confidence = existing_record.get("confidence") or 0.0
                if bool(existing_record.get("passed", False)) or verdict == "CONFIRMED":
                    review_state.mark_result_confirmed(
                        result_file,
                        cycle,
                        current_fingerprint or "",
                        verdict="CONFIRMED",
                        confidence=float(confidence or 0.0),
                        feedback=reason,
                    )
                    apply_result_review_verdict(
                        working_dir=work_dir,
                        results_dir=results_dir,
                        result_file=result_file,
                        verdict="CONFIRMED",
                        passed=True,
                        confidence=float(confidence or 0.0),
                        feedback=reason,
                        cycle=cycle,
                        fingerprint=current_fingerprint or "",
                    )
                    logger.info(
                        "result_review_resume_skip_existing_advisor",
                        result_file=result_file,
                        advisor=advisor_def.instance_id,
                        cycle=cycle,
                    )
                    continue
                if verdict == "FALSE_POSITIVE":
                    review_state.mark_result_false_positive(
                        result_file,
                        cycle,
                        current_fingerprint or "",
                        verdict="FALSE_POSITIVE",
                        confidence=float(confidence or 0.0),
                        feedback=reason,
                    )
                apply_result_review_verdict(
                    working_dir=work_dir,
                    results_dir=results_dir,
                    result_file=result_file,
                    verdict="FALSE_POSITIVE",
                    passed=False,
                    confidence=float(confidence or 0.0),
                    feedback=reason,
                    cycle=cycle,
                    fingerprint=current_fingerprint or "",
                )
                return True

            agent = self.agents.get(advisor_def.agent_id)

            # 构建 prompt (R7)
            system_prompt = read_file(advisor_def.system_prompt_file)
            user_prompt_tpl = read_file(advisor_def.user_prompt_template)
            user_prompt = render_string(
                user_prompt_tpl,
                strict=True,
                result_filename=result_file,
                cycle=str(cycle),
                task_file=task_file,
                result_file=result_path,
                supporting_docs_dir=review_context["supporting_docs_dir"],
                optional_supporting_docs=review_context["optional_supporting_docs"],
                result_review_context=review_context["context_text"],
            )

            # 会话管理（结果评审必须按“结果文件”隔离会话）
            # reset_context=True  → 每次新建 session (独立客观)
            # reset_context=False → 仅复用同一 result_file 的历史 session，
            #                       避免不同结果文件之间相互污染，也避免并发复用同一 session
            session_key = f"result::{advisor_def.instance_id}::{result_file}"
            session_id = advisor_sessions.get(session_key)
            should_reset = agent.should_reset_context()
            session_hint = self._build_result_review_session_hint(
                advisor_def=advisor_def,
                cycle=cycle,
                result_file=result_file,
            )
            retry_limit = review_runtime_retry_limit(agent)
            runtime_retries_used = 0

            step_key = f"result::{result_file}::{advisor_def.instance_id}"
            response = None
            guard_before = None
            early_violations: list[str] = []
            try:
                for attempt_index in range(retry_limit + 1):
                    if attempt_index > 0:
                        runtime_retries_used = attempt_index
                        if session_id:
                            with contextlib.suppress(Exception):
                                await agent.close_session(session_id)
                            if advisor_sessions.get(session_key) == session_id:
                                advisor_sessions.pop(session_key, None)
                        session_id = await agent.create_session_with_hint(
                            retry_session_hint(session_hint, attempt_index)
                        )
                        advisor_sessions[session_key] = session_id
                    elif should_reset or session_id is None:
                        session_id = await agent.create_session_with_hint(session_hint)
                        advisor_sessions[session_key] = session_id

                    record_step_checkpoint(
                        work_dir,
                        cycle=cycle,
                        phase="result_review",
                        step_key=step_key,
                        status="started",
                        agent_id=advisor_def.agent_id,
                        session_id=session_id,
                        extra={
                            "result_file": result_file,
                            "advisor_instance_id": advisor_def.instance_id,
                            "attempt": attempt_index + 1,
                            "runtime_retry_limit": retry_limit,
                        },
                    )

                    guard_before = take_read_only_snapshot(work_dir)
                    response = await agent.send_message(
                        message=user_prompt,
                        system_prompt=system_prompt,
                        session_id=session_id,
                        working_dir=work_dir,
                    )
                    early_violations = diff_read_only_snapshots(
                        guard_before,
                        take_read_only_snapshot(work_dir),
                    )
                    if (
                        not early_violations
                        and is_retryable_review_runtime_error(response)
                        and attempt_index < retry_limit
                    ):
                        logger.warning(
                            "result_review_agent_runtime_retry",
                            result_file=result_file,
                            advisor=advisor_def.instance_id,
                            cycle=cycle,
                            attempt=attempt_index + 1,
                            retry_limit=retry_limit,
                            error=response.error,
                            error_code=response.error_code,
                        )
                        record_step_checkpoint(
                            work_dir,
                            cycle=cycle,
                            phase="result_review",
                            step_key=step_key,
                            status="retrying",
                            agent_id=advisor_def.agent_id,
                            session_id=session_id,
                            detail=str(response.error or ""),
                            extra={
                                "result_file": result_file,
                                "advisor_instance_id": advisor_def.instance_id,
                                "attempt": attempt_index + 1,
                                "next_retry": attempt_index + 1,
                                "runtime_retry_limit": retry_limit,
                                "error_code": response.error_code,
                            },
                        )
                        continue
                    break

                if response is None or guard_before is None:
                    raise RuntimeError("result review advisor did not produce a response")

                if not response.success:
                    reason = f"Agent错误：{response.error}"
                    if response.error_code:
                        reason = f"[{response.error_code}] {reason}"
                    reason = append_retry_summary(
                        reason,
                        retries_used=runtime_retries_used,
                        retry_limit=retry_limit,
                    )
                    if early_violations:
                        reason = f"{reason}\n\n{format_read_only_violations(early_violations)}"
                    await self.recorder.record_result_review(
                        work_dir=work_dir,
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        cycle=cycle, passed=False, content=reason,
                        agent_id=advisor_def.agent_id,
                        role_name=advisor_def.role_name,
                        raw_content=response.content if response.content else "",
                        verdict="ERROR",
                        detail_feedback=reason,
                        schema_valid=False,
                        parser_mode="agent_error",
                        repair_attempts=0,
                    )
                    record_step_checkpoint(
                        work_dir,
                        cycle=cycle,
                        phase="result_review",
                        step_key=step_key,
                        status="failed",
                        agent_id=advisor_def.agent_id,
                        session_id=session_id,
                        detail=reason,
                        extra={
                            "runtime_retries_used": runtime_retries_used,
                            "runtime_retry_limit": retry_limit,
                        },
                    )
                    raise ResultReviewFrameworkError(
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        reason=reason,
                        error_code=response.error_code,
                    )

                parse_outcome, repair_attempts, raw_chain = await self._parse_with_schema_repair(
                    agent=agent,
                    session_id=session_id,
                    system_prompt=system_prompt,
                    working_dir=work_dir,
                    result_file=result_file,
                    review_context_hint=review_context["repair_hint"],
                    initial_response_content=response.content or "",
                )
                if not parse_outcome.schema_valid:
                    reason = parse_outcome.repair_reason or "结果评审未返回 canonical JSON"
                    await self.recorder.record_result_review(
                        work_dir=work_dir,
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        cycle=cycle,
                        passed=False,
                        content=reason,
                        agent_id=advisor_def.agent_id,
                        role_name=advisor_def.role_name,
                        raw_content=raw_chain,
                        verdict="ERROR",
                        detail_feedback=reason,
                        schema_valid=False,
                        parser_mode=parse_outcome.parser_mode,
                        repair_attempts=repair_attempts,
                    )
                    record_step_checkpoint(
                        work_dir,
                        cycle=cycle,
                        phase="result_review",
                        step_key=step_key,
                        status="failed",
                        agent_id=advisor_def.agent_id,
                        session_id=session_id,
                        detail=reason,
                    )
                    raise ResultReviewFrameworkError(
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        reason=reason,
                        error_code="result_review_schema_invalid",
                    )
                parsed = parse_outcome.parsed

                violations = diff_read_only_snapshots(
                    guard_before,
                    take_read_only_snapshot(work_dir),
                )
                if violations:
                    violation_feedback = format_read_only_violations(violations)
                    logger.error(
                        "result_review_read_only_violation",
                        result_file=result_file,
                        advisor=advisor_def.instance_id,
                        cycle=cycle,
                        violations=violations,
                    )
                    await self.recorder.record_result_review(
                        work_dir=work_dir,
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        cycle=cycle,
                        passed=False,
                        content="结果评审 advisor 违反只读契约",
                        agent_id=advisor_def.agent_id,
                        role_name=advisor_def.role_name,
                        scores=parsed.scores or {},
                        confidence=0.0,
                        raw_content=raw_chain,
                        verdict="ERROR",
                        detail_feedback=violation_feedback,
                        schema_valid=False,
                        parser_mode="read_only_violation",
                        repair_attempts=repair_attempts,
                    )
                    record_step_checkpoint(
                        work_dir,
                        cycle=cycle,
                        phase="result_review",
                        step_key=step_key,
                        status="failed",
                        agent_id=advisor_def.agent_id,
                        session_id=session_id,
                        detail=violation_feedback,
                    )
                    raise ResultReviewFrameworkError(
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        reason=violation_feedback,
                        error_code="advisor_read_only_violation",
                    )

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
                    raw_content=raw_chain,
                    verdict=parsed.verdict,
                    detail_feedback=parsed.feedback_detail,
                    schema_valid=parse_outcome.schema_valid,
                    parser_mode=parse_outcome.parser_mode,
                    repair_attempts=repair_attempts,
                )

                if parsed.verdict == "FALSE_POSITIVE":
                    review_state.mark_result_false_positive(
                        result_file,
                        cycle,
                        current_fingerprint or "",
                        verdict=parsed.verdict,
                        confidence=parsed.confidence,
                        feedback=parsed.feedback_detail or parsed.feedback,
                    )
                elif parsed.passed or parsed.verdict == "CONFIRMED":
                    review_state.mark_result_confirmed(
                        result_file,
                        cycle,
                        current_fingerprint or "",
                        verdict="CONFIRMED",
                        confidence=parsed.confidence,
                        feedback=parsed.feedback_detail or parsed.feedback,
                    )
                else:
                    raise ResultReviewFrameworkError(
                        result_file=result_file,
                        advisor_id=advisor_def.instance_id,
                        reason=f"结果评审返回了非法 business verdict: {parsed.verdict or '<empty>'}",
                        error_code="result_review_invalid_verdict",
                    )
                apply_result_review_verdict(
                    working_dir=work_dir,
                    results_dir=results_dir,
                    result_file=result_file,
                    verdict=parsed.verdict,
                    passed=parsed.passed,
                    confidence=parsed.confidence,
                    feedback=parsed.feedback_detail or parsed.feedback,
                    cycle=cycle,
                    fingerprint=current_fingerprint or "",
                )

                record_step_checkpoint(
                    work_dir,
                    cycle=cycle,
                    phase="result_review",
                    step_key=step_key,
                    status="completed",
                    agent_id=advisor_def.agent_id,
                    session_id=session_id,
                    extra={
                        "passed": True,
                        "repair_attempts": repair_attempts,
                        "runtime_retries_used": runtime_retries_used,
                        "runtime_retry_limit": retry_limit,
                    },
                )
            finally:
                close_after_call = (
                    should_reset
                    or response is None
                    or (response is not None and not response.success)
                    or bool(early_violations)
                )
                if close_after_call and session_id:
                    with contextlib.suppress(Exception):
                        await agent.close_session(session_id)
                    if advisor_sessions.get(session_key) == session_id:
                        advisor_sessions.pop(session_key, None)

        return True

    async def _parse_with_schema_repair(
        self,
        *,
        agent,
        session_id: str,
        system_prompt: str,
        working_dir: str,
        result_file: str,
        review_context_hint: str,
        initial_response_content: str,
    ) -> tuple[ResultReviewParseOutcome, int, str]:
        parse_outcome = parse_result_review_response(initial_response_content)
        repair_attempts = 0
        raw_chain = initial_response_content or ""

        while parse_outcome.needs_repair and repair_attempts < _RESULT_REVIEW_SCHEMA_REPAIR_LIMIT:
            repair_attempts += 1
            logger.warning(
                "result_review_schema_invalid",
                result_file=result_file,
                session_id=session_id,
                parser_mode=parse_outcome.parser_mode,
                reason=parse_outcome.repair_reason,
                repair_attempt=repair_attempts,
            )
            repair_prompt = self._build_schema_repair_prompt(
                result_file=result_file,
                review_context_hint=review_context_hint,
                parse_outcome=parse_outcome,
            )
            repair_response = await agent.send_message(
                message=repair_prompt,
                system_prompt=system_prompt,
                session_id=session_id,
                working_dir=working_dir,
            )
            if not repair_response.success:
                logger.warning(
                    "result_review_schema_repair_failed",
                    result_file=result_file,
                    session_id=session_id,
                    error=repair_response.error,
                    repair_attempt=repair_attempts,
                )
                break

            repair_content = repair_response.content or ""
            raw_chain = self._merge_raw_response_chain(raw_chain, repair_content, repair_attempts)
            parse_outcome = parse_result_review_response(repair_content)

        return parse_outcome, repair_attempts, raw_chain

    @staticmethod
    def _build_schema_repair_prompt(
        *,
        result_file: str,
        review_context_hint: str,
        parse_outcome: ResultReviewParseOutcome,
    ) -> str:
        reason = parse_outcome.repair_reason or "上一次输出未满足结果评审 JSON schema"
        return (
            f"你刚才对 `{result_file}` 的结果评审输出未满足框架 schema：{reason}\n\n"
            "不要重新做代码分析；只基于你刚才已经形成的判断，把结论重编码为**一个 JSON 对象**。\n"
            "再次提醒：result review 的唯一通过标准是**底层问题是否真实存在、是否不是误报**。\n"
            "以下情况如果底层问题真实存在，仍然必须判通过（passed=true, verdict=CONFIRMED）：\n"
            "- 严重度高估\n"
            "- 攻击路径闭环不完整\n"
            "- taint source 说错\n"
            "- 仅在高权限 / 配置错误 / 特定前提下触发\n"
            "- 这是一份补充分析 / correction / supplement / VALID_CORRECTION 报告\n\n"
            "只有以下两类情况判不通过：\n"
            "1. FALSE_POSITIVE：问题本身不存在，或被遗漏的完整检查有效阻断\n"
            "2. 如果证据不完整，也必须基于现有材料在 CONFIRMED / FALSE_POSITIVE 中二选一，并在 feedback 说明不确定点；禁止输出 INSUFFICIENT_INFO。\n\n"
            "严格要求：\n"
            "1. 只能输出一个 JSON 对象，禁止任何前言、总结、解释、Markdown 代码块。\n"
            "2. verdict 只能是 CONFIRMED / FALSE_POSITIVE，禁止使用 INSUFFICIENT_INFO、UNVERIFIED、VALID_CORRECTION、REAL、TRUE_POSITIVE_WITH_CAVEATS、verification_result 等 alias。\n"
            "3. scores 必须是对象，且必须包含唯一必需字段 `issue_truth`，字段值必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW。\n"
            "4. confidence 也必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW。\n\n"
            "严格输出：\n"
            "{\n"
            '  "passed": true 或 false,\n'
            '  "verdict": "CONFIRMED" | "FALSE_POSITIVE",\n'
            '  "feedback": "一句话说明结论；若通过，可顺带写需要修正的严重度/攻击链/前提等",\n'
            '  "scores": {"issue_truth": 0.0},\n'
            '  "confidence": 0.0\n'
            "}\n\n"
            "禁止输出 Markdown 代码块、禁止前言后记、禁止使用 verification_result / verification_status / final_verdict 作为顶层键。\n"
            f"如果你需要回忆上下文，请依赖当前 session 与本轮评审对象：{review_context_hint}。"
        )

    @staticmethod
    def _merge_raw_response_chain(original: str, repaired: str, repair_attempt: int) -> str:
        if not original:
            return repaired
        if not repaired:
            return original
        return (
            f"[original_response]\n{original}\n\n"
            f"[schema_repair_attempt_{repair_attempt}]\n{repaired}"
        )
