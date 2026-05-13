"""
全局评审执行器 (R6f)

- 评审对象: 原始任务 + 总结报告 + 结果清单
- 多个全局评审参谋智能体 **并行** 执行，所有参谋独立评审后合并结果
- 任何一个不通过 → 整体不通过 → 回到 Worker (R6g)
- 默认 re_review_on_cycle=True
- 评审 prompt 只传“评审入口文件路径”，避免把 summary / task 全文塞进 prompt
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
from pathlib import Path
from typing import Any

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef, EngineConfig
from app.pi_vuln_core.engine.checkpoint import record_step_checkpoint
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review_parser import (
    GlobalReviewParseOutcome,
    parse_global_review_response,
)
from app.pi_vuln_core.review.advisor_runtime_retry import (
    append_retry_summary,
    is_retryable_review_runtime_error,
    retry_session_hint,
    review_runtime_retry_limit,
)
from app.pi_vuln_core.review.previous_limitations import (
    load_previous_limitations,
)
from app.pi_vuln_core.review.read_only_guard import (
    diff_read_only_snapshots,
    format_read_only_violations,
    take_read_only_snapshot,
)
from app.pi_vuln_core.review.profile import (
    format_review_profile_policy,
    get_review_profile_policy,
)
from app.pi_vuln_core.review.state import ReviewState, GlobalReviewRecord
from app.pi_vuln_core.utils.file_ops import read_file, read_json, write_json
from app.pi_vuln_core.utils.result_docs import (
    classify_final_result_files,
    coverage_ledger_path,
    format_coverage_obligation_summary,
    list_result_report_files,
    list_supporting_markdown_files,
    results_manifest_path,
)
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("global_review")


async def _already_done(payload: dict):
    return payload


_KNOWN_SCORE_KEYS: tuple[str, ...] = (
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "vuln_pattern_breadth",
    "code_evidence_depth",
    "limitations_honesty",
    "report_completeness",
)

_GLOBAL_REVIEW_SCHEMA_REPAIR_LIMIT = 2

_PROFILE_PATTERN_FAMILY_LABELS: dict[str, str] = {
    "memory_safety": "memory_safety/内存安全",
    "integer_safety": "integer_safety/整数安全",
    "input_validation": "input_validation/输入校验",
    "logic_state": "logic_state/逻辑状态",
    "resource_lifetime": "resource_lifetime/资源生命周期",
    "concurrency_timing": "concurrency_timing/并发时序",
}

_PROFILE_PATTERN_FAMILY_PATTERNS: dict[str, re.Pattern[str]] = {
    "memory_safety": re.compile(
        r"(?i)(内存安全|越界|缓冲区|堆|栈|use[- ]?after[- ]?free|uaf|"
        r"double[- ]?free|buffer|memcpy|memset|copy|overflow)"
    ),
    "integer_safety": re.compile(
        r"(?i)(整数|溢出|下溢|截断|回绕|符号|signed|unsigned|integer|"
        r"underflow|wrap|truncate|RAW_U(?:8|16|32|64)|长度)"
    ),
    "input_validation": re.compile(
        r"(?i)(输入校验|输入验证|合法性|边界值|绕过|校验|validation|"
        r"sanitize|sanitise|check|boundary)"
    ),
    "logic_state": re.compile(
        r"(?i)(逻辑|状态机|状态|分支|路径|条件|绕过|state|logic|"
        r"state machine|bypass)"
    ),
    "resource_lifetime": re.compile(
        r"(?i)(资源|生命周期|泄漏|释放|引用计数|malloc|free|fd|"
        r"resource|lifetime|leak|cleanup)"
    ),
    "concurrency_timing": re.compile(
        r"(?i)(并发|竞争|时序|锁|TOCTOU|race|concurr|timing|lock)"
    ),
}


class GlobalReviewExecutor:
    """
    全局评审执行器

    并行调用每个全局评审参谋，任一不通过则整体不通过。
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
        engine_config: EngineConfig | None = None,
        resume_cursor: dict | None = None,
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
        review_profile = (
            engine_config.review_profile if engine_config is not None else "fast"
        )
        review_context = self._build_review_context_text(
            task_file=task_file,
            summary_file=summary_file,
            results_dir=results_dir,
            work_dir=work_dir,
            cycle=cycle,
            review_state=review_state,
            review_profile=review_profile,
        )

        active_advisors = [
            advisor_def for advisor_def in advisors_cfg
            if not (cycle > 1 and not advisor_def.re_review_on_cycle)
        ]
        for advisor_def in advisors_cfg:
            if advisor_def not in active_advisors:
                logger.debug(
                    "skip_global_review",
                    advisor=advisor_def.instance_id,
                    reason="re_review_on_cycle=False",
                )

        # 并行执行所有 advisor；resume 时已落盘的 advisor 记录直接复用，
        # 只重跑缺失/中断的具体 advisor。
        tasks = []
        for index, advisor_def in enumerate(active_advisors, start=1):
            existing = self._load_existing_global_review_record(
                work_dir=work_dir,
                cycle=cycle,
                advisor_def=advisor_def,
            )
            if existing is not None:
                logger.info(
                    "global_review_resume_skip_existing_advisor",
                    advisor=advisor_def.instance_id,
                    cycle=cycle,
                    resume_cursor=resume_cursor or {},
                )
                tasks.append(_already_done(existing))
                continue
            tasks.append(self._run_single_advisor(
                advisor_def=advisor_def,
                index=index,
                total_advisors=len(active_advisors),
                review_context=review_context,
                task_file=task_file,
                results_dir=results_dir,
                work_dir=work_dir,
                cycle=cycle,
                review_state=review_state,
                advisor_sessions=advisor_sessions,
            ))
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        # 合并结果
        all_passed = True
        aggregate_scores: dict[str, float] = {}
        all_issues: list[dict] = []
        feedback_parts: list[str] = []

        for advisor_def, outcome in zip(active_advisors, outcomes):
            if isinstance(outcome, BaseException):
                all_passed = False
                error_feedback = f"评审智能体异常：{outcome}"
                framework_issue = self._advisor_runtime_issue(
                    advisor_def.instance_id,
                    error_feedback,
                )
                feedback_parts.append(error_feedback)
                all_issues.append(framework_issue)
                review_state.global_review_history.append(
                    GlobalReviewRecord(
                        cycle=cycle,
                        advisor_id=advisor_def.instance_id,
                        role_name=advisor_def.role_name,
                        passed=False,
                        feedback=error_feedback,
                        issues=[framework_issue],
                    )
                )
                logger.error(
                    "global_review_advisor_exception",
                    advisor=advisor_def.instance_id,
                    cycle=cycle,
                    error=str(outcome),
                )
                continue

            aggregate_scores = self._merge_scores_min(
                aggregate_scores, outcome["scores"],
            )
            outcome_issues = self._enrich_advisor_issues(
                outcome.get("issues", []),
                advisor_id=str(outcome.get("advisor_id") or advisor_def.instance_id),
            )
            if not outcome.get("already_recorded"):
                review_state.global_review_history.append(
                    GlobalReviewRecord(
                        cycle=cycle,
                        advisor_id=advisor_def.instance_id,
                        passed=outcome["passed"],
                        feedback=outcome["detail_feedback"] or outcome["feedback"],
                        scores=outcome["scores"] or {},
                        issues=outcome_issues,
                    )
                )

            if not outcome["passed"]:
                all_passed = False
                all_issues.extend(outcome_issues)
                feedback_parts.append(
                    outcome["detail_feedback"] or outcome["feedback"]
                )

        profile_issues = self._profile_gate_issues(
            work_dir=work_dir,
            review_profile=review_profile,
        )
        if profile_issues:
            all_passed = False
            all_issues.extend(profile_issues)
            feedback_parts.append(self._format_profile_gate_feedback(profile_issues))

        if all_passed:
            review_state.record_global_review_result(
                cycle=cycle,
                passed=True,
                feedback="全局评审通过",
                scores=aggregate_scores,
                issues=[],
            )
            self._write_review_feedback_snapshot(work_dir, cycle, review_state)
            return True, ""

        combined_feedback = "\n\n".join(feedback_parts)
        review_state.record_global_review_result(
            cycle=cycle,
            passed=False,
            feedback=combined_feedback,
            scores=aggregate_scores,
            issues=all_issues,
        )
        self._write_review_feedback_snapshot(work_dir, cycle, review_state)
        return False, combined_feedback

    @staticmethod
    def _load_existing_global_review_record(
        *,
        work_dir: str,
        cycle: int,
        advisor_def: AdvisorInstanceDef,
    ) -> dict | None:
        record_path = (
            Path(work_dir)
            / "reviews"
            / "global"
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
        # agent_error 是运行层错误，不应在 resume 时固化为业务评审结论。
        if parser_mode == "agent_error" or verdict == "ERROR":
            return None
        feedback = str(data.get("feedback") or "")
        detail_feedback = str(data.get("feedback_detail") or feedback)
        return {
            "advisor_id": advisor_def.instance_id,
            "role_name": advisor_def.role_name,
            "passed": bool(data.get("passed", False)),
            "feedback": feedback,
            "detail_feedback": detail_feedback,
            "scores": data.get("scores") or {},
            "issues": data.get("issues") or [],
            "already_recorded": True,
        }

    async def _run_single_advisor(
        self,
        *,
        advisor_def: AdvisorInstanceDef,
        index: int,
        total_advisors: int,
        review_context: dict[str, str],
        task_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        advisor_sessions: dict[str, str],
    ) -> dict:
        """执行单个全局评审参谋，返回结构化结果。"""
        agent = self.agents.get(advisor_def.agent_id)
        worker_system_prompt_file = self._infer_worker_system_prompt_file(advisor_def)

        system_prompt = read_file(advisor_def.system_prompt_file)
        user_prompt_tpl = read_file(advisor_def.user_prompt_template)
        required_score_keys = self._required_score_keys_for_advisor(advisor_def)
        user_prompt = render_string(
            user_prompt_tpl,
            strict=True,
            cycle=str(cycle),
            workflow_mode=review_state.workflow_mode,
            current_issue_count=str(len(review_state.get_recent_issues(last_n=2))),
            task_file=task_file,
            summary_file=review_context["summary_file"],
            results_dir=results_dir,
            supporting_docs_dir=review_context["supporting_docs_dir"],
            previous_limitations_file=review_context["previous_limitations_file"],
            result_relations_manifest_file=review_context["result_relations_manifest_file"],
            results_manifest_file=review_context["results_manifest_file"],
            coverage_ledger_file=review_context["coverage_ledger_file"],
            review_context=review_context["context_text"],
            advisor_instance_id=advisor_def.instance_id,
            advisor_role_name=advisor_def.role_name,
            current_global_review_index=str(index),
            total_global_review_advisors=str(total_advisors),
            prior_global_findings="(本轮全局评审并行执行，各参谋独立评审)",
            worker_system_prompt_file=worker_system_prompt_file,
            score_thresholds=self._format_score_thresholds_for_advisor(advisor_def, cycle),
            required_score_fields=self._format_required_score_fields_for_advisor(advisor_def),
            closure_review_policy=self._format_closure_review_policy(review_state.workflow_mode),
        )

        session_key = advisor_def.instance_id
        session_id = advisor_sessions.get(session_key)
        should_reset = agent.should_reset_context()
        session_hint = self._build_global_review_session_hint(
            advisor_def=advisor_def,
            cycle=cycle,
            total_advisors=total_advisors,
        )
        retry_limit = review_runtime_retry_limit(agent)
        runtime_retries_used = 0

        logger.info(
            "global_review_start",
            advisor=advisor_def.instance_id,
            cycle=cycle,
            summary_file=review_context["summary_file"],
            result_relations_manifest_file=review_context["result_relations_manifest_file"],
            results_manifest_file=review_context["results_manifest_file"],
            coverage_ledger_file=review_context["coverage_ledger_file"],
        )
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
                    phase="global_review",
                    step_key=f"global::{advisor_def.instance_id}",
                    status="started",
                    agent_id=advisor_def.agent_id,
                    session_id=session_id,
                    extra={
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
                        "global_review_agent_runtime_retry",
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
                        phase="global_review",
                        step_key=f"global::{advisor_def.instance_id}",
                        status="retrying",
                        agent_id=advisor_def.agent_id,
                        session_id=session_id,
                        detail=str(response.error or ""),
                        extra={
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
                raise RuntimeError("global review advisor did not produce a response")

            if not response.success:
                logger.error(
                    "global_review_agent_error",
                    advisor=advisor_def.instance_id,
                    error=response.error,
                )
                feedback = f"评审智能体错误：{response.error}"
                feedback = append_retry_summary(
                    feedback,
                    retries_used=runtime_retries_used,
                    retry_limit=retry_limit,
                )
                fallback_issues = [
                    self._advisor_runtime_issue(advisor_def.instance_id, feedback)
                ]
                if early_violations:
                    violation_feedback = format_read_only_violations(early_violations)
                    feedback = f"{feedback}\n\n{violation_feedback}"
                    fallback_issues.extend(
                        self._read_only_violation_issues(
                            advisor_def.instance_id,
                            early_violations,
                        )
                    )
                await self._record(
                    work_dir,
                    advisor_def,
                    cycle,
                    False,
                    feedback,
                    raw_content=response.content if response.content else "",
                    verdict="ERROR",
                    detail_feedback=feedback,
                    issues=fallback_issues,
                    resolved_issue_ids=[],
                    workflow_mode=review_state.workflow_mode,
                )
                record_step_checkpoint(
                    work_dir,
                    cycle=cycle,
                    phase="global_review",
                    step_key=f"global::{advisor_def.instance_id}",
                    status="failed",
                    agent_id=advisor_def.agent_id,
                    session_id=session_id,
                    detail=feedback,
                    extra={
                        "runtime_retries_used": runtime_retries_used,
                        "runtime_retry_limit": retry_limit,
                    },
                )
                return {
                    "advisor_id": advisor_def.instance_id,
                    "role_name": advisor_def.role_name,
                    "passed": False,
                    "feedback": feedback,
                    "detail_feedback": feedback,
                    "scores": {},
                    "issues": fallback_issues,
                }

            parse_outcome, repair_attempts, raw_chain = await self._parse_with_schema_repair(
                agent=agent,
                session_id=session_id,
                system_prompt=system_prompt,
                working_dir=work_dir,
                review_context_hint=review_context["repair_hint"],
                initial_response_content=response.content or "",
                required_score_keys=required_score_keys,
            )
            parsed = parse_outcome.parsed
            resolved_issue_ids = list(parsed.resolved_issue_ids or [])

            if not parse_outcome.schema_valid:
                issues = self._schema_invalid_issues(
                    parse_outcome.repair_reason, advisor_def.instance_id,
                )
                effective_passed = False
                effective_verdict = "FAIL"
                effective_feedback = f"FAIL（未通过） - {issues[0]['detail']}"[:300]
                base_detail = (parsed.feedback_detail or parsed.feedback or "").strip()
                schema_detail = (
                    parse_outcome.repair_reason
                    or "全局评审输出未满足 canonical JSON schema"
                )
                effective_detail_feedback = (
                    f"{base_detail}\n\n[global review schema invalid] {schema_detail}"
                    if base_detail else
                    f"[global review schema invalid] {schema_detail}"
                )
            else:
                (
                    effective_passed,
                    effective_feedback,
                    effective_detail_feedback,
                    effective_verdict,
                    threshold_issues,
                    ) = self._apply_score_thresholds(
                        parsed,
                        advisor_def,
                        cycle,
                        workflow_mode=review_state.workflow_mode,
                    )
                model_issues = list(parsed.issues or [])
                issues = (
                    model_issues
                    if not effective_passed and model_issues
                    else threshold_issues
                    if not effective_passed and threshold_issues
                    else [{"source": advisor_def.instance_id, "detail": effective_detail_feedback or effective_feedback}]
                    if not effective_passed else []
                )

            violations = diff_read_only_snapshots(
                guard_before,
                take_read_only_snapshot(work_dir),
            )
            if violations:
                violation_feedback = format_read_only_violations(violations)
                logger.error(
                    "global_review_read_only_violation",
                    advisor=advisor_def.instance_id,
                    cycle=cycle,
                    violations=violations,
                )
                effective_passed = False
                effective_verdict = "FAIL"
                effective_feedback = "FAIL（未通过） - advisor 违反只读评审契约"
                effective_detail_feedback = (
                    f"{effective_detail_feedback}\n\n{violation_feedback}"
                    if effective_detail_feedback else violation_feedback
                )
                issues = list(issues or []) + self._read_only_violation_issues(
                    advisor_def.instance_id,
                    violations,
                )

            await self._record(
                work_dir,
                advisor_def,
                cycle,
                effective_passed,
                effective_feedback,
                parsed.scores,
                parsed.confidence,
                raw_chain,
                effective_verdict,
                effective_detail_feedback,
                issues,
                resolved_issue_ids,
                review_state.workflow_mode,
                parse_outcome.schema_valid,
                parse_outcome.parser_mode,
                repair_attempts,
            )

            record_step_checkpoint(
                work_dir,
                cycle=cycle,
                phase="global_review",
                step_key=f"global::{advisor_def.instance_id}",
                status="completed",
                agent_id=advisor_def.agent_id,
                session_id=session_id,
                extra={
                    "passed": effective_passed,
                    "repair_attempts": repair_attempts,
                    "runtime_retries_used": runtime_retries_used,
                    "runtime_retry_limit": retry_limit,
                },
            )
            logger.info(
                "global_review_result",
                advisor=advisor_def.instance_id,
                cycle=cycle,
                passed=effective_passed,
                issue_count=(0 if effective_passed else len(issues)),
                scores=parsed.scores,
            )

            return {
                "advisor_id": advisor_def.instance_id,
                "role_name": advisor_def.role_name,
                "passed": effective_passed,
                "feedback": effective_feedback,
                "detail_feedback": effective_detail_feedback,
                "scores": parsed.scores or {},
                "issues": issues,
            }
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

    @staticmethod
    def _enrich_advisor_issues(
        issues: list[dict[str, Any]] | None,
        *,
        advisor_id: str,
    ) -> list[dict[str, Any]]:
        enriched: list[dict[str, Any]] = []
        for item in issues or []:
            issue = dict(item) if isinstance(item, dict) else {"detail": str(item)}
            if advisor_id and not issue.get("advisor_id"):
                issue["advisor_id"] = advisor_id
            enriched.append(issue)
        return enriched

    @staticmethod
    def _build_global_review_session_hint(
        *,
        advisor_def: AdvisorInstanceDef,
        cycle: int,
        total_advisors: int,
    ) -> str:
        if total_advisors <= 1 and advisor_def.instance_id in {"global_quality", "global-review", "global_review"}:
            return f"global_review_cycle_{cycle:03d}"
        return f"global_review_cycle_{cycle:03d}_{advisor_def.instance_id}"

    @staticmethod
    def _merge_unique_ids(existing: list[str], incoming: list[str]) -> list[str]:
        merged = list(existing)
        for item in incoming:
            text = str(item).strip()
            if text and text not in merged:
                merged.append(text)
        return merged

    @staticmethod
    def _merge_scores_min(existing: dict[str, float], incoming: dict[str, float]) -> dict[str, float]:
        if not existing:
            return dict(incoming or {})
        if not incoming:
            return dict(existing)

        merged = dict(existing)
        for key, value in incoming.items():
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                numeric = 0.0
            if key not in merged:
                merged[key] = numeric
                continue
            try:
                merged[key] = min(float(merged[key]), numeric)
            except (TypeError, ValueError):
                merged[key] = numeric
        return merged

    @staticmethod
    def _prefix_issue_id(advisor_id: str, issue_id: str) -> str:
        issue_id = str(issue_id or "").strip()
        advisor_id = str(advisor_id or "").strip()
        if not issue_id or not advisor_id:
            return issue_id
        if advisor_id in {"global_review", "global_quality", "global-review"}:
            return issue_id
        if issue_id.startswith(f"{advisor_id}:"):
            return issue_id
        return f"{advisor_id}:{issue_id}"

    @staticmethod
    def _infer_worker_system_prompt_file(advisor_def: AdvisorInstanceDef) -> str:
        candidate = Path(advisor_def.user_prompt_template).with_name("worker_system.md")
        return str(candidate) if candidate.is_file() else ""

    @staticmethod
    def _required_score_keys_for_advisor(advisor_def: AdvisorInstanceDef) -> list[str]:
        return [str(key).strip() for key in advisor_def.score_fields if str(key).strip()]

    @classmethod
    def _thresholds_for_advisor(cls, advisor_def: AdvisorInstanceDef, cycle: int = 1) -> dict[str, float]:
        fields = cls._required_score_keys_for_advisor(advisor_def)
        final = {
            key: float(advisor_def.score_thresholds[key])
            for key in fields
            if key in advisor_def.score_thresholds
        }
        start = {
            key: float((advisor_def.score_thresholds_start or advisor_def.score_thresholds).get(key, final[key]))
            for key in final
        }
        ramp_cycles = max(1, int(advisor_def.score_threshold_ramp_cycles or 1))
        t = 1.0 if ramp_cycles <= 1 else min(1.0, max(0.0, (cycle - 1) / float(ramp_cycles - 1)))
        return {
            key: round(start[key] + t * (final[key] - start[key]), 2)
            for key in fields
            if key in final and key in start
        }

    @classmethod
    def _format_score_thresholds_for_advisor(cls, advisor_def: AdvisorInstanceDef, cycle: int = 1) -> str:
        thresholds = cls._thresholds_for_advisor(advisor_def, cycle)
        final = advisor_def.score_thresholds or {}
        lines: list[str] = []
        for key in cls._required_score_keys_for_advisor(advisor_def):
            if key not in thresholds:
                continue
            current = thresholds[key]
            target = float(final[key])
            if abs(current - target) < 0.01:
                lines.append(f"- `{key}`: ≥ {current:.2f}")
            else:
                lines.append(f"- `{key}`: ≥ {current:.2f}（本轮）→ {target:.2f}（最终）")
        if not lines:
            return "(无专属分数阈值)"
        lines.insert(0, f"当前轮次: Cycle {cycle}（阈值随轮次渐进提升）")
        return "\n".join(lines)

    @classmethod
    def _format_required_score_fields_for_advisor(cls, advisor_def: AdvisorInstanceDef) -> str:
        return ", ".join(
            f"`{key}`" for key in cls._required_score_keys_for_advisor(advisor_def)
        )

    @staticmethod
    def _format_prior_advisor_findings(prior_outcomes: list[dict[str, object]]) -> str:
        if not prior_outcomes:
            return "(本轮暂无已完成的上游全局评审结果)"

        lines: list[str] = []
        for item in prior_outcomes:
            advisor_id = str(item.get("advisor_id") or "")
            role_name = str(item.get("role_name") or advisor_id)
            passed = bool(item.get("passed"))
            feedback = str(item.get("feedback") or "").strip().replace("\n", " ")
            if len(feedback) > 260:
                feedback = feedback[:260] + "..."
            resolved = [str(v).strip() for v in (item.get("resolved_issue_ids") or []) if str(v).strip()]
            issues = item.get("issues") or []

            lines.append(f"- [{advisor_id}] {role_name}: {'PASS' if passed else 'FAIL'}")
            if feedback:
                lines.append(f"  - feedback_preview: {feedback}")
            if resolved:
                lines.append(f"  - resolved_issues: {', '.join(resolved)}")
            if issues:
                issue_ids = [
                    ReviewState.prompt_safe_issue_id(issue.get('id') or '')
                    for issue in issues
                    if str(issue.get('id') or '').strip()
                ]
                if issue_ids:
                    lines.append(f"  - issues: {', '.join(issue_ids)}")
        return "\n".join(lines)

    def _build_review_context_text(
        self,
        *,
        task_file: str,
        summary_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
        review_profile: str = "balanced",
    ) -> dict[str, str]:
        current_result_files = list_result_report_files(results_dir)
        final_selection = classify_final_result_files(results_dir, summary_file)
        passed_results = set(review_state.get_passed_result_filenames(current_result_files))
        failed_results = set(review_state.get_failed_result_filenames(current_result_files))
        pending_results = [
            name for name in current_result_files
            if name not in passed_results and name not in failed_results
        ]
        supporting_docs_dir = Path(work_dir) / "supporting_docs"
        supporting_docs = list_supporting_markdown_files(supporting_docs_dir)
        previous_limitations, previous_meta = self._load_previous_limitations(work_dir, cycle)
        result_relations_manifest_file = Path(work_dir) / "_meta" / "result_relations_manifest.json"
        results_manifest_file = results_manifest_path(work_dir)
        coverage_ledger_file = coverage_ledger_path(work_dir)
        coverage_obligation_summary = self._format_coverage_obligation_context(coverage_ledger_file)
        # 轻量反馈链：注入最近轮次的评审反馈，同时保留 active issue backlog。
        recent_feedback = self._format_recent_review_feedback(review_state, cycle)
        open_issue_backlog = review_state.format_open_issue_backlog(max_items=12)
        final_results = final_selection.get("final_results") or []
        excluded_results = final_selection.get("excluded_results") or []

        lines = [
            "## 当前评审对象",
            f"- 当前轮次：{cycle}",
            f"- 当前工作模式：{review_state.workflow_mode}",
            f"- 任务文件: `{task_file}`",
            f"- 总结报告: `{summary_file}`",
            f"- 结果目录: `{results_dir}`",
            f"- 辅助文档目录: `{supporting_docs_dir}`",
            f"- 上一轮局限性来源: {previous_meta.get('kind', '')} (轮次={previous_meta.get('cycle', 0)})",
            f"- 结果关系清单: `{result_relations_manifest_file}`",
            f"- 结果生命周期清单: `{results_manifest_file}`",
            f"- 框架覆盖账本: `{coverage_ledger_file}`",
            "",
            "## 开始前必须读取",
            "- task、summary、results manifest、coverage ledger（路径见上）",
        ]
        if previous_limitations.strip():
            lines.append("- 上一轮局限性章节（已内联在下方）")
        if final_results:
            lines.append(
                "- final result files: "
                + ", ".join(f"`results/{name}`" for name in final_results)
            )
        else:
            lines.append(f"- `{results_dir}` 下当前存在的所有 `result_NNN.md`")
        if supporting_docs:
            lines.append(
                "- supporting docs: "
                + ", ".join(f"`supporting_docs/{name}`" for name in supporting_docs)
            )
        lines.extend([
            "",
            "## 当前结果状态摘要（评审前快照）",
            f"- 全部结果: {', '.join(current_result_files) if current_result_files else '(无)'}",
            f"- 最终结果: {', '.join(final_results) if final_results else '(无)'}",
            f"- 排除结果: {', '.join(excluded_results) if excluded_results else '(无)'}",
            f"- 已通过: {', '.join(sorted(passed_results)) if passed_results else '(无)'}",
            f"- 未通过: {', '.join(sorted(failed_results)) if failed_results else '(无)'}",
            f"- 待评审: {', '.join(pending_results) if pending_results else '(无)'}",
            f"- 辅助文档: {', '.join(supporting_docs) if supporting_docs else '(无)'}",
        ])
        lines.extend([
            "",
            format_review_profile_policy(review_profile, compact=True),
            "",
            coverage_obligation_summary,
        ])
        if open_issue_backlog:
            lines.extend([
                "",
                "## Active issue backlog（跨轮稳定阻塞项）",
                open_issue_backlog,
            ])
        if review_state.workflow_mode == "closure":
            lines.extend([
                "",
                "## Closure 评审模式",
                "- 当前已进入 closure：优先验证 active issue backlog 和 coverage ledger 的 open obligations 是否按本轮验收要求被关闭、接受 residual、标记 unused/not_applicable 或 external_blocked。",
                "- 不要把本轮评审重新展开成无限全量重扫；新 blocker 只允许针对 coverage ledger 中具体 obligation，或明确高严重度且可验证的新增遗漏。",
                "- 若 Worker 已给出 source_closed/accepted_residual/unused/not_applicable/external_blocked 且证据自洽，应接受 closure，不要反复要求无新增信息的继续分析。",
            ])
        if recent_feedback:
            lines.extend([
                "",
                "## 近期评审反馈（供参考）",
                recent_feedback,
            ])
        else:
            lines.extend([
                "",
                "## 近期评审反馈",
                "(无历史评审反馈)",
            ])
        repeated_issues = review_state.format_issue_ledger_summary(
            min_consecutive=2,
            max_items=5,
        )
        if repeated_issues:
            lines.extend([
                "",
                "## 重复阻塞项 ledger（框架检测）",
                repeated_issues,
                "",
                "- 若同一 issue 仍未闭环，请复用相同 id，并补充 `blocking_type` 与 `acceptance_criteria`。",
                "- 若 Worker 已给出 residual 证据且确实受外部源码/上下文限制，请将 blocker 标为 `needs_external_source` 或接受 summary 的 residual 说明；不要反复要求无新增信息的“继续分析”。",
            ])
        if previous_limitations.strip():
            lines.extend([
                "",
                "## 上一轮“局限性与未覆盖区域”章节（用于核对是否被静默删除）",
                previous_limitations.strip(),
            ])

        repair_hint = (
            f"task=`{task_file}`, summary=`{summary_file}`, results_dir=`{results_dir}`, "
            f"supporting_docs_dir=`{supporting_docs_dir}`, previous_limitations_source={previous_meta.get('kind', '')}"
        )
        return {
            "summary_file": summary_file,
            "supporting_docs_dir": str(supporting_docs_dir),
            "previous_limitations_file": str(previous_meta.get("path") or ""),
            "result_relations_manifest_file": str(result_relations_manifest_file),
            "results_manifest_file": str(results_manifest_file),
            "coverage_ledger_file": str(coverage_ledger_file),
            "context_text": "\n".join(lines),
            "repair_hint": repair_hint,
        }

    async def _parse_with_schema_repair(
        self,
        *,
        agent,
        session_id: str,
        system_prompt: str,
        working_dir: str,
        review_context_hint: str,
        initial_response_content: str,
        required_score_keys: list[str] | None = None,
    ) -> tuple[GlobalReviewParseOutcome, int, str]:
        parse_outcome = parse_global_review_response(
            initial_response_content,
            required_score_keys=required_score_keys,
        )
        repair_attempts = 0
        raw_chain = initial_response_content or ""

        while parse_outcome.needs_repair and repair_attempts < _GLOBAL_REVIEW_SCHEMA_REPAIR_LIMIT:
            repair_attempts += 1
            logger.warning(
                "global_review_schema_invalid",
                session_id=session_id,
                parser_mode=parse_outcome.parser_mode,
                reason=parse_outcome.repair_reason,
                repair_attempt=repair_attempts,
            )
            repair_prompt = self._build_schema_repair_prompt(
                review_context_hint=review_context_hint,
                parse_outcome=parse_outcome,
                required_score_keys=required_score_keys,
            )
            repair_response = await agent.send_message(
                message=repair_prompt,
                system_prompt=system_prompt,
                session_id=session_id,
                working_dir=working_dir,
            )
            if not repair_response.success:
                logger.warning(
                    "global_review_schema_repair_failed",
                    session_id=session_id,
                    error=repair_response.error,
                    repair_attempt=repair_attempts,
                )
                break

            repair_content = repair_response.content or ""
            raw_chain = self._merge_raw_response_chain(raw_chain, repair_content, repair_attempts)
            parse_outcome = parse_global_review_response(
                repair_content,
                required_score_keys=required_score_keys,
            )

        return parse_outcome, repair_attempts, raw_chain

    @staticmethod
    def _build_schema_repair_prompt(
        *,
        review_context_hint: str,
        parse_outcome: GlobalReviewParseOutcome,
        required_score_keys: list[str] | None = None,
    ) -> str:
        reason = parse_outcome.repair_reason or "上一次输出未满足全局评审 JSON schema"
        score_keys = list(required_score_keys or _KNOWN_SCORE_KEYS)
        score_lines = ",\n".join(
            f'    "{key}": 0.0'
            for key in score_keys
        )
        return (
            f"你刚才的全局评审输出未满足框架 schema：{reason}\n\n"
            "不要重新做全面审计；只基于你刚才已经形成的判断，把结论重编码为**一个 JSON 对象**。\n"
            "严格要求：\n"
            "1. 只能输出一个 JSON 对象，禁止任何前言、总结、解释、Markdown 代码块。\n"
            "2. 顶层必须至少包含：passed / feedback / scores / confidence。\n"
            "3. `scores` 不能为空，且只需包含本评审角色负责的必需字段，字段值必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW。\n"
            "4. `confidence` 也必须是 0.0-1.0 数值，不能写 HIGH/MEDIUM/LOW。\n"
            "5. 如果保留 `verdict`，只能是 PASS 或 FAIL。\n"
            "6. 如果输出 `issues` / `resolved_issues`，它们必须分别是数组。passed=true 时 issues 必须为空数组。\n"
            "7. passed=false 时，每个 issue 必须包含 actionable_by：worker / summary / framework 三选一。\n"
            "8. passed=false 时，每个 issue 应包含 blocking_type 与 acceptance_criteria：\n"
            "   blocking_type 取值建议：analysis_gap / evidence_gap / summary_sync / framework_contract / needs_external_source / accepted_residual。\n"
            "   acceptance_criteria 写清下一轮怎样才算关闭该 issue。\n\n"
            "请按下面 schema 直接返回：\n"
            "{\n"
            '  "passed": true 或 false,\n'
            '  "verdict": "PASS" 或 "FAIL",\n'
            '  "feedback": "简明判定摘要",\n'
            '  "scores": {\n'
            f"{score_lines}\n"
            "  },\n"
            '  "confidence": 0.0,\n'
            '  "issues": [{"id": "stable-id", "category": "coverage_gap", "target": "symbol-or-file", "severity": "high", "required_action": "具体动作", "actionable_by": "worker", "blocking_type": "analysis_gap", "acceptance_criteria": "可验证关闭条件"}],\n'
            '  "resolved_issues": []\n'
            "}\n\n"
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

    def _schema_invalid_issues(self, reason: str, advisor_id: str = "global_review") -> list[dict[str, str]]:
        detail = reason or "全局评审输出未满足 canonical JSON schema"
        return [{
            "id": self._prefix_issue_id(advisor_id, "schema-contract"),
            "category": "schema_contract",
            "target": "reviews/global",
            "severity": "high",
            "required_action": "framework/advisor 必须返回包含本角色必需 scores 的 canonical JSON；当前输出未满足 schema。",
            "detail": detail[:800],
            "owner": "framework",
            "actionable_by": "framework",
            "blocking_type": "framework_contract",
            "acceptance_criteria": "advisor 按 canonical JSON schema 重新输出，并包含本角色必需 scores。",
        }]

    @staticmethod
    def _advisor_runtime_issue(advisor_id: str, detail: str) -> dict[str, str]:
        return {
            "source": advisor_id,
            "category": "advisor_runtime",
            "target": "reviews/global",
            "severity": "high",
            "detail": detail[:800],
            "owner": "framework",
            "actionable_by": "framework",
            "blocking_type": "framework_contract",
            "acceptance_criteria": "advisor runtime 恢复正常，评审阶段可返回 canonical JSON。",
        }

    def _read_only_violation_issues(
        self,
        advisor_id: str,
        violations: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        paths = ", ".join(
            f"{item.get('change', '')}:{item.get('path', '')}"
            for item in violations[:8]
        )
        return [{
            "id": self._prefix_issue_id(advisor_id, "read-only-violation"),
            "category": "advisor_contract",
            "target": "workspace",
            "severity": "high",
            "required_action": "框架必须阻断或重跑违反只读契约的 advisor；advisor 评审阶段不得修改工作产物。",
            "detail": paths[:800],
                "owner": "framework",
                "actionable_by": "framework",
                "blocking_type": "framework_contract",
                "acceptance_criteria": "advisor 评审阶段不再修改 workspace；违规修改已回滚或隔离。",
            }]

    def _apply_score_thresholds(
        self,
        parsed,
        advisor_def: AdvisorInstanceDef,
        cycle: int = 1,
        *,
        workflow_mode: str = "discovery",
    ) -> tuple[bool, str, str, str, list[dict[str, str]]]:
        if parsed.passed and workflow_mode == "closure":
            return (
                parsed.passed,
                parsed.feedback,
                parsed.feedback_detail,
                parsed.verdict,
                [],
            )
        threshold_issues = self._score_threshold_issues(parsed.scores or {}, advisor_def, cycle)
        if not parsed.passed or not threshold_issues:
            return (
                parsed.passed,
                parsed.feedback,
                parsed.feedback_detail,
                parsed.verdict,
                [],
            )

        threshold_feedback = self._format_score_threshold_feedback(threshold_issues)
        base_detail = (parsed.feedback_detail or parsed.feedback or "").strip()
        detail = (
            f"{base_detail}\n\n{threshold_feedback}"
            if base_detail else threshold_feedback
        )
        feedback = f"FAIL（未通过） - {threshold_issues[0]['detail']}"[:300]
        return False, feedback, detail, "FAIL", threshold_issues

    def _score_threshold_issues(self, scores: dict[str, float], advisor_def: AdvisorInstanceDef, cycle: int = 1) -> list[dict[str, str]]:
        if not scores:
            return []

        advisor_id = advisor_def.instance_id
        thresholds = self._thresholds_for_advisor(advisor_def, cycle)
        issues: list[dict[str, str]] = []
        for key, threshold in thresholds.items():
            if key not in scores:
                continue
            try:
                actual = float(scores[key])
            except (TypeError, ValueError):
                actual = 0.0
            if actual + 1e-9 >= threshold:
                continue
            detail = f"{key}={actual:.2f} 低于本轮通过阈值 {threshold:.2f}（Cycle {cycle}）"
            issues.append({
                "id": self._prefix_issue_id(advisor_id, f"score-threshold:{key.replace('_', '-') }"),
                "category": "score_threshold",
                "target": key,
                "severity": "high",
                "required_action": (
                    f"补齐 {key} 对应的分析证据，或将该分数提升到至少 {threshold:.2f} 后再通过全局评审"
                ),
                "detail": detail,
                "owner": "worker",
                "actionable_by": "worker",
                "blocking_type": "evidence_gap",
                "acceptance_criteria": f"{key} 分数达到本轮阈值 {threshold:.2f}，或 summary 中诚实说明不可闭环 residual。",
            })
        return issues

    @staticmethod
    def _format_score_threshold_feedback(issues: list[dict[str, str]]) -> str:
        lines = ["[框架分数阈值校验未通过]"]
        lines.extend(f"- {item['detail']}" for item in issues)
        return "\n".join(lines)

    @staticmethod
    def _profile_gate_issues(
        *,
        work_dir: str,
        review_profile: str,
    ) -> list[dict[str, str]]:
        policy = get_review_profile_policy(review_profile)
        if not policy.enforce_coverage_gate:
            return []

        ledger_file = coverage_ledger_path(work_dir)
        if not ledger_file.is_file():
            return [{
                "id": f"PROFILE-{policy.name}-coverage-ledger-missing",
                "category": "coverage_gate",
                "target": str(ledger_file),
                "severity": "high",
                "required_action": "重新同步 coverage ledger；summary 阶段必须生成 `_meta/coverage_ledger.json` 后才能通过本轮验收。",
                "detail": "本轮验收要求 coverage gate，但 coverage ledger 不存在。",
                "owner": "framework",
                "actionable_by": "framework",
                "blocking_type": "metadata_sync",
                "acceptance_criteria": "`_meta/coverage_ledger.json` 存在，且包含 data-flow/task-derived coverage_obligations。",
            }]

        try:
            ledger = read_json(ledger_file)
        except Exception as exc:
            return [{
                "id": f"PROFILE-{policy.name}-coverage-ledger-unreadable",
                "category": "coverage_gate",
                "target": str(ledger_file),
                "severity": "high",
                "required_action": "修复 coverage ledger JSON，使框架可以读取并执行 profile gate。",
                "detail": f"读取 coverage ledger 失败：{exc}",
                "owner": "framework",
                "actionable_by": "framework",
                "blocking_type": "metadata_sync",
                "acceptance_criteria": "`_meta/coverage_ledger.json` 是合法 JSON。",
            }]

        obligations = ledger.get("coverage_obligations") or {}
        if not isinstance(obligations, dict):
            obligations = {}
        entries = [
            item for item in (obligations.get("entries") or [])
            if isinstance(item, dict)
        ]
        open_entries = [
            item for item in entries
            if not bool(item.get("documented")) or str(item.get("status") or "") == "open"
        ]

        issues: list[dict[str, str]] = []
        quality = obligations.get("quality") or {}
        declared_total = 0
        if isinstance(quality, dict):
            declared_counts = quality.get("declared_counts") or {}
            if isinstance(declared_counts, dict):
                for key in ("input", "export", "used", "cleaned", "star"):
                    try:
                        declared_total += int(declared_counts.get(key) or 0)
                    except (TypeError, ValueError):
                        pass
        total = len(entries)
        if (
            policy.require_dataflow_extraction
            and declared_total >= 10
            and total < max(1, int(declared_total * policy.min_declared_extraction_ratio))
        ):
            issues.append({
                "id": f"PROFILE-{policy.name}-coverage-under-extracted",
                "category": "coverage_gate",
                "target": str(ledger_file),
                "severity": "high",
                "required_action": "从原始 data-flow 文件抽取端点级 INPUT/EXPORT/USED/CLEANED/STAR obligations，而不是只抽 task.md 摘要。",
                "detail": (
                    f"本轮验收要求端点级账本；task 声明约 {declared_total} 个义务，"
                    f"当前 ledger 仅 {total} 个，低于 {policy.min_declared_extraction_ratio:.0%} 抽取下限。"
                ),
                "owner": "framework",
                "actionable_by": "framework",
                "blocking_type": "coverage_ledger_under_extracted",
                "acceptance_criteria": "coverage_ledger.coverage_obligations.entries 覆盖原始 data-flow 的主要端点，至少达到本轮验收要求的抽取比例。",
            })

        required_risks = set(policy.required_risks)
        required_kinds = set(policy.required_kinds)
        blocking_open = [
            item for item in open_entries
            if str(item.get("risk") or "medium").lower() in required_risks
            or str(item.get("kind") or "").lower() in required_kinds
        ]
        if blocking_open:
            preview = "; ".join(
                f"{item.get('id')}[{item.get('risk') or 'medium'}]"
                for item in blocking_open[:10]
            )
            issues.append({
                "id": f"PROFILE-{policy.name}-coverage-open-required",
                "category": "coverage_gate",
                "target": str(ledger_file),
                "severity": "high",
                "required_action": (
                    f"关闭本轮必须闭环的 open obligations：{preview}"
                ),
                "detail": (
                    f"本轮验收不允许 {len(blocking_open)} 个 "
                    "STAR/高风险/指定风险等级 coverage obligations 仍为 open。"
                ),
                "owner": "worker",
                "actionable_by": "worker",
                "blocking_type": "coverage_obligation_open",
                "acceptance_criteria": "相关 obligations 在 ledger 中变为 documented，并在 result/supporting_docs/summary 中给出 source_closed/promoted_to_result/accepted_residual/unused/not_applicable/external_blocked 证据。",
            })

        if not policy.allow_summary_only_evidence:
            summary_only = [
                item for item in entries
                if bool(item.get("documented"))
                and str(item.get("risk") or "medium").lower() in required_risks
                and set(item.get("evidence_sources") or []) == {"summary.md"}
            ]
            if summary_only:
                preview = "; ".join(str(item.get("id") or "") for item in summary_only[:10])
                issues.append({
                    "id": f"PROFILE-{policy.name}-summary-only-evidence",
                    "category": "coverage_gate",
                    "target": str(ledger_file),
                    "severity": "high",
                    "required_action": "为高/中风险 obligations 补充 result 或 supporting_docs 源码证据；summary-only 不能作为本轮验收的充分证据。",
                    "detail": f"以下 obligations 只有 summary.md 证据：{preview}",
                    "owner": "worker",
                    "actionable_by": "worker",
                    "blocking_type": "summary_only_evidence",
                    "acceptance_criteria": "相关 obligations 的 evidence_sources 至少包含 results/*.md 或 supporting_docs/*.md。",
                })

        issues.extend(
            GlobalReviewExecutor._profile_evidence_artifact_issues(
                work_dir=work_dir,
                policy=policy,
            )
        )
        issues.extend(
            GlobalReviewExecutor._profile_pattern_family_issues(
                work_dir=work_dir,
                policy=policy,
            )
        )
        return issues

    @staticmethod
    def _profile_evidence_artifact_issues(
        *,
        work_dir: str,
        policy,
    ) -> list[dict[str, str]]:
        required_count = int(getattr(policy, "min_evidence_artifacts", 0) or 0)
        if required_count <= 0:
            return []
        if not GlobalReviewExecutor._profile_has_coverage_surface(work_dir):
            return []

        work_path = Path(work_dir)
        results_dir = work_path / "results"
        summary_file = work_path / "summary.md"
        supporting_docs_dir = work_path / "supporting_docs"
        try:
            selection = classify_final_result_files(
                results_dir,
                summary_file if summary_file.is_file() else None,
            )
            result_count = len(selection.get("taskable_results") or [])
        except Exception:
            result_count = len(list_result_report_files(results_dir))
        supporting_count = len(list_supporting_markdown_files(supporting_docs_dir))
        artifact_count = result_count + supporting_count
        if artifact_count >= required_count:
            return []

        return [{
            "id": f"PROFILE-{policy.name}-evidence-artifact-floor",
            "category": "profile_evidence_gate",
            "target": str(work_path),
            "severity": "medium" if policy.name in {"fast", "balanced"} else "high",
            "required_action": (
                f"本轮范围至少需要 {required_count} 个证据产物；"
                "若无新增漏洞，用 supporting_docs 记录源码级负面证据、模式覆盖和 residual 边界。"
            ),
            "detail": (
                f"本轮验收要求 evidence artifacts >= {required_count}，"
                f"当前 taskable results={result_count}, supporting_docs={supporting_count}, "
                f"total={artifact_count}。"
            ),
            "owner": "worker",
            "actionable_by": "worker",
            "blocking_type": "profile_evidence_floor",
            "acceptance_criteria": (
                "results/*.md 或 supporting_docs/*.md 中留下足够的源码级正/负证据；"
                "深度验收不能只复用初步 summary 结论。"
            ),
        }]

    @staticmethod
    def _profile_pattern_family_issues(
        *,
        work_dir: str,
        policy,
    ) -> list[dict[str, str]]:
        required = [
            str(item)
            for item in (getattr(policy, "required_pattern_families", ()) or ())
            if str(item).strip()
        ]
        if not required:
            return []
        if not GlobalReviewExecutor._profile_has_coverage_surface(work_dir):
            return []

        corpus = GlobalReviewExecutor._read_profile_evidence_corpus(work_dir)
        missing = [
            family for family in required
            if not _PROFILE_PATTERN_FAMILY_PATTERNS.get(
                family,
                re.compile(re.escape(family), re.IGNORECASE),
            ).search(corpus)
        ]
        if not missing:
            return []

        missing_labels = ", ".join(
            _PROFILE_PATTERN_FAMILY_LABELS.get(item, item)
            for item in missing
        )
        return [{
            "id": f"PROFILE-{policy.name}-pattern-family-coverage",
            "category": "profile_evidence_gate",
            "target": str(Path(work_dir)),
            "severity": "medium" if policy.name == "balanced" else "high",
            "required_action": (
                "补齐本轮要求的漏洞模式族扫描记录；缺失模式族："
                f"{missing_labels}。"
            ),
            "detail": (
                "本轮验收要求在 summary/results/supporting_docs 中"
                f"留下模式族覆盖或不适用证据；当前缺失：{missing_labels}。"
            ),
            "owner": "worker",
            "actionable_by": "worker",
            "blocking_type": "profile_pattern_family_gap",
            "acceptance_criteria": (
                "对缺失模式族补充源码级正/负扫描结论；若不适用，"
                "在 supporting_docs 中明确 not_applicable/accepted_residual 及原因。"
            ),
        }]

    @staticmethod
    def _profile_has_coverage_surface(work_dir: str) -> bool:
        ledger_file = coverage_ledger_path(work_dir)
        if not ledger_file.is_file():
            return False
        try:
            ledger = read_json(ledger_file)
        except Exception:
            return False
        obligations = ledger.get("coverage_obligations") or {}
        if not isinstance(obligations, dict):
            return False
        try:
            total = int(obligations.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        quality = obligations.get("quality") or {}
        declared_total = 0
        if isinstance(quality, dict):
            try:
                declared_total = int(quality.get("declared_total") or 0)
            except (TypeError, ValueError):
                declared_total = 0
        return total > 0 or declared_total > 0

    @staticmethod
    def _read_profile_evidence_corpus(work_dir: str) -> str:
        work_path = Path(work_dir)
        parts: list[str] = []

        def append_file(path: Path) -> None:
            if not path.is_file():
                return
            try:
                parts.append(read_file(path)[:200_000])
            except Exception:
                return

        append_file(work_path / "summary.md")
        results_dir = work_path / "results"
        for name in list_result_report_files(results_dir):
            append_file(results_dir / name)
        supporting_docs_dir = work_path / "supporting_docs"
        for name in list_supporting_markdown_files(supporting_docs_dir):
            append_file(supporting_docs_dir / name)
        return "\n".join(parts)

    @staticmethod
    def _format_profile_gate_feedback(issues: list[dict[str, str]]) -> str:
        if not issues:
            return ""
        lines = ["[框架范围验收硬门槛未通过]"]
        for item in issues:
            lines.append(f"- {ReviewState.prompt_safe_issue_id(item.get('id'))}: {item.get('detail')}")
        return "\n".join(lines)

    @staticmethod
    def _format_closure_review_policy(workflow_mode: str) -> str:
        if workflow_mode != "closure":
            return (
                "- discovery 模式：可以做全量覆盖/深度审计，但 issue 必须指向具体 obligation、函数或文件，并给出可验证 acceptance_criteria。"
            )
        return "\n".join([
            "- closure 模式：本轮不是重新发散漏洞挖掘，而是验证仍影响漏洞真实性、漏报风险或误报风险的 active issues / coverage signals。",
            "- 优先检查 `_meta/coverage_ledger.json` 中高风险、靠近 sink、被评审点名的 open signals，以及 `_meta/issue_ledger.json` 的 active entries。",
            "- 若高价值 signal 已在 summary/supporting_docs/results 中以 source_closed、promoted_to_result、accepted_residual、unused、not_applicable 或 external_blocked 自洽处理，应判定该项关闭。",
            "- 只有发现具体、可验证、且会影响最终结论的高严重遗漏时才新增 issue；不要用笼统的“继续深入/仍不够全面”阻断。",
        ])

    @staticmethod
    def _format_coverage_obligation_context(coverage_ledger_file: Path) -> str:
        if not coverage_ledger_file.is_file():
            return (
                "## Coverage / issue radar\n"
                f"- `{coverage_ledger_file}` 尚不存在；若本轮 summary 已生成但账本缺失，应标记 framework/metadata_sync。"
            )
        try:
            ledger = read_json(coverage_ledger_file)
        except Exception as exc:
            return f"## Coverage / issue radar\n- 读取 `{coverage_ledger_file}` 失败：{exc}"
        return format_coverage_obligation_summary(ledger, max_open=12)

    def _write_review_feedback_snapshot(
        self,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
    ) -> None:
        snapshot_dir = Path(work_dir) / "_meta" / "review_feedback"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        current_issues = review_state.get_current_issue_records()
        write_json(
            snapshot_dir / f"cycle_{cycle:03d}.json",
            {
                "cycle": cycle,
                "workflow_mode": review_state.workflow_mode,
                "issue_count": len(current_issues),
                "issues": current_issues,
                "issue_ledger_status": review_state.get_issue_ledger_status(),
                "last_global_scores": review_state.last_global_scores,
                "last_global_feedback": review_state.last_global_feedback,
            },
        )

    def _load_previous_limitations(
        self,
        work_dir: str,
        cycle: int,
    ) -> tuple[str, dict[str, str | int | bool]]:
        return load_previous_limitations(work_dir, cycle)

    @staticmethod
    def _extract_markdown_section(content: str, titles: list[str]) -> str:
        """提取 markdown 中指定标题章节的正文（包含标题行）"""
        if not content:
            return ""
        lines = content.splitlines()
        start_idx = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue
            normalized = re.sub(r"^#+\s*", "", stripped)
            normalized = re.sub(r"^\d+(?:\.\d+)*\s*[.、]?\s*", "", normalized).strip()
            if any(title in normalized for title in titles):
                start_idx = i
                break
        if start_idx is None:
            return ""

        end_idx = len(lines)
        for j in range(start_idx + 1, len(lines)):
            if lines[j].strip().startswith("#"):
                end_idx = j
                break
        return "\n".join(lines[start_idx:end_idx]).strip()

    @staticmethod
    def _is_substantive_limitations(content: str) -> bool:
        if not content or not content.strip():
            return False

        payload_lines: list[str] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            normalized = re.sub(r"^#+\s*", "", line)
            normalized = re.sub(r"^\d+(?:\.\d+)*\s*[.、]?\s*", "", normalized).strip()
            if "局限性与未覆盖区域" in normalized or normalized == "局限性":
                continue
            if "详见" in line and "previous_limitations" in line:
                continue
            if re.fullmatch(r"[>`*_\-\s]+", line):
                continue
            payload_lines.append(line)

        return bool(payload_lines)

    @staticmethod
    def _format_recent_review_feedback(review_state: ReviewState, cycle: int) -> str:
        """格式化最近轮次的评审反馈，供参谋参考。"""
        return review_state.format_recent_feedback(last_n=2)

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
        issues: list[dict] | None = None,
        resolved_issue_ids: list[str] | None = None,
        workflow_mode: str = "",
        schema_valid: bool | None = None,
        parser_mode: str = "",
        repair_attempts: int = 0,
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
            issues=issues,
            resolved_issue_ids=resolved_issue_ids,
            workflow_mode=workflow_mode,
            schema_valid=schema_valid,
            parser_mode=parser_mode,
            repair_attempts=repair_attempts,
        )
