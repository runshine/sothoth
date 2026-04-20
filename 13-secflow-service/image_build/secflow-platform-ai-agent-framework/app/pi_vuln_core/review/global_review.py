"""
全局评审执行器 (R6f)

- 评审对象: 原始任务 + 总结报告 + 结果清单
- 多个全局评审参谋智能体 **串行** 执行
- 任何一个不通过 → 整体不通过 → 回到 Worker (R6g)
- 默认 re_review_on_cycle=True
- 评审 prompt 只传“评审入口文件路径”，避免把 summary / task 全文塞进 prompt
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.models import parse_review_response
from app.pi_vuln_core.review.previous_limitations import load_previous_limitations
from app.pi_vuln_core.review.state import ReviewState, GlobalReviewRecord
from app.pi_vuln_core.utils.file_ops import read_file, write_file, write_json
from app.pi_vuln_core.utils.result_docs import (
    list_result_report_files,
    list_supporting_markdown_files,
)
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
        packet = self._build_review_packet(
            task_file=task_file,
            summary_file=summary_file,
            results_dir=results_dir,
            work_dir=work_dir,
            cycle=cycle,
            review_state=review_state,
        )

        for advisor_def in advisors_cfg:
            # 检查是否需要本轮评审
            if cycle > 1 and not advisor_def.re_review_on_cycle:
                logger.debug(
                    "skip_global_review",
                    advisor=advisor_def.instance_id,
                    reason="re_review_on_cycle=False",
                )
                continue

            agent = self.agents.get(advisor_def.agent_id)

            # 构建 prompt (R7)
            system_prompt = read_file(advisor_def.system_prompt_file)
            user_prompt_tpl = read_file(advisor_def.user_prompt_template)
            user_prompt = render_string(
                user_prompt_tpl,
                cycle=str(cycle),
                workflow_mode=review_state.workflow_mode,
                review_packet_path=packet["review_packet_path"],
                task_file=task_file,
                summary_file=packet["summary_file"],
                results_dir=results_dir,
                results_manifest_file=packet["results_manifest_file"],
                previous_limitations_file=packet["previous_limitations_file"],
                supporting_docs_dir=packet["supporting_docs_dir"],
                supporting_docs_manifest_file=packet["supporting_docs_manifest_file"],
                open_blockers_file=packet["open_blockers_file"],
                current_open_blocker_count=str(len(review_state.get_open_blockers())),
            )

            # 会话管理
            session_id = advisor_sessions.get(advisor_def.instance_id)
            should_reset = agent.should_reset_context()

            if should_reset or session_id is None:
                session_id = await agent.create_session()
                advisor_sessions[advisor_def.instance_id] = session_id

            # 调用评审
            logger.info(
                "global_review_start",
                advisor=advisor_def.instance_id,
                cycle=cycle,
                review_packet=packet["review_packet_path"],
            )

            response = await agent.send_message(
                message=user_prompt,
                system_prompt=system_prompt,
                session_id=session_id,
                working_dir=work_dir,
            )

            if not response.success:
                logger.error(
                    "global_review_agent_error",
                    advisor=advisor_def.instance_id,
                    error=response.error,
                )
                # Agent 错误视为不通过
                feedback = f"评审智能体错误: {response.error}"
                fallback_blockers = self._fallback_blockers(feedback)
                review_state.record_global_review_result(
                    cycle=cycle,
                    passed=False,
                    feedback=feedback,
                    scores={},
                    blocking_issues=fallback_blockers,
                    resolved_issue_ids=[],
                )
                self._write_blocker_snapshot(work_dir, cycle, review_state)
                await self._record(
                    work_dir,
                    advisor_def,
                    cycle,
                    False,
                    feedback,
                    raw_content=response.content if response.content else "",
                    verdict="ERROR",
                    detail_feedback=feedback,
                    blocking_issues=fallback_blockers,
                    resolved_issue_ids=[],
                    workflow_mode=review_state.workflow_mode,
                )
                review_state.global_review_history.append(
                    GlobalReviewRecord(
                        cycle=cycle,
                        advisor_id=advisor_def.instance_id,
                        passed=False,
                        feedback=feedback,
                    )
                )
                return False, feedback

            # 解析评审结果
            parsed = parse_review_response(response.content)
            blocking_issues = (
                parsed.blocking_issues
                if not parsed.passed and parsed.blocking_issues
                else self._fallback_blockers(parsed.feedback_detail or parsed.feedback)
                if not parsed.passed else []
            )
            review_state.last_global_scores = dict(parsed.scores or {})
            review_state.last_global_feedback = parsed.feedback_detail or parsed.feedback
            if not parsed.passed:
                review_state.record_global_review_result(
                    cycle=cycle,
                    passed=False,
                    feedback=parsed.feedback_detail or parsed.feedback,
                    scores=parsed.scores,
                    blocking_issues=blocking_issues,
                    resolved_issue_ids=parsed.resolved_issue_ids,
                )
                self._write_blocker_snapshot(work_dir, cycle, review_state)

            # 记录 (R6h)
            await self._record(
                work_dir,
                advisor_def,
                cycle,
                parsed.passed,
                parsed.feedback,
                parsed.scores,
                parsed.confidence,
                parsed.raw_content,
                parsed.verdict,
                parsed.feedback_detail,
                blocking_issues,
                parsed.resolved_issue_ids,
                review_state.workflow_mode,
            )

            review_state.global_review_history.append(
                GlobalReviewRecord(
                    cycle=cycle,
                    advisor_id=advisor_def.instance_id,
                    passed=parsed.passed,
                    feedback=parsed.feedback_detail or parsed.feedback,
                )
            )

            logger.info(
                "global_review_result",
                advisor=advisor_def.instance_id,
                cycle=cycle,
                passed=parsed.passed,
                open_blockers=(0 if parsed.passed else len(review_state.get_open_blockers())),
                scores=parsed.scores,
            )

            # 任何一个不通过 → 立即返回 (R6g)
            if not parsed.passed:
                return False, (parsed.feedback_detail or parsed.feedback)

        # 全部通过：清空阻塞 backlog（已通过说明 blocking issues 已全部关闭）
        review_state.record_global_review_result(
            cycle=cycle,
            passed=True,
            feedback="全局评审通过",
            scores=review_state.last_global_scores,
            blocking_issues=[],
            resolved_issue_ids=[],
        )
        self._write_blocker_snapshot(work_dir, cycle, review_state)
        return True, ""

    def _build_review_packet(
        self,
        *,
        task_file: str,
        summary_file: str,
        results_dir: str,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
    ) -> dict[str, str]:
        packet_dir = Path(work_dir) / "_meta" / "review_packets" / f"cycle_{cycle:03d}"
        packet_dir.mkdir(parents=True, exist_ok=True)

        previous_limitations, previous_limitations_meta = self._load_previous_limitations(
            work_dir,
            cycle,
        )
        previous_limitations_file = packet_dir / "previous_limitations.md"
        write_file(previous_limitations_file, previous_limitations)

        current_result_files = list_result_report_files(results_dir)
        results_manifest = []
        passed_results = set(review_state.get_passed_result_filenames(current_result_files))
        failed_results = set(review_state.get_failed_result_filenames(current_result_files))
        pending_results = [
            name for name in current_result_files
            if name not in passed_results and name not in failed_results
        ]
        for name in current_result_files:
            path = Path(results_dir) / name
            try:
                stat = path.stat()
                is_passed = name in passed_results
                is_failed = name in failed_results
                review_status = (
                    "passed" if is_passed else
                    "failed" if is_failed else
                    "pending_review"
                )
                results_manifest.append({
                    "filename": name,
                    "size_bytes": stat.st_size,
                    "passed": is_passed,
                    "failed": is_failed,
                    "review_status": review_status,
                })
            except FileNotFoundError:
                continue

        results_manifest_file = packet_dir / "results_manifest.json"
        write_json(results_manifest_file, {
            "cycle": cycle,
            "results_dir": results_dir,
            "review_status_snapshot_phase": "pre_result_review",
            "reviewer_instruction": (
                "这是本轮 result review 开始前的结果状态快照。"
                " `passed=false, failed=false` 表示该结果尚未进入当前轮结果评审，"
                "不应仅因其仍是 pending_review 就判定为元数据不一致。"
            ),
            "total_results": len(results_manifest),
            "results": results_manifest,
        })

        supporting_docs_dir = Path(work_dir) / "supporting_docs"
        supporting_docs_manifest = []
        for name in list_supporting_markdown_files(supporting_docs_dir):
            path = supporting_docs_dir / name
            try:
                stat = path.stat()
                supporting_docs_manifest.append({
                    "filename": name,
                    "relative_path": f"supporting_docs/{name}",
                    "size_bytes": stat.st_size,
                })
            except FileNotFoundError:
                continue

        supporting_docs_manifest_file = packet_dir / "supporting_docs_manifest.json"
        write_json(supporting_docs_manifest_file, {
            "cycle": cycle,
            "supporting_docs_dir": str(supporting_docs_dir),
            "total_supporting_docs": len(supporting_docs_manifest),
            "supporting_docs": supporting_docs_manifest,
        })

        open_blockers = review_state.serialize_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
        )
        open_blockers_note = self._get_open_blockers_sync_note()
        open_blockers_file = packet_dir / "open_blockers.json"
        write_json(open_blockers_file, {
            "cycle": cycle,
            "workflow_mode": review_state.workflow_mode,
            "snapshot_phase": "pre_review",
            "reviewer_instruction": open_blockers_note,
            "open_count": len(open_blockers),
            "blockers": open_blockers,
        })

        historical_removed_result_count = len(sorted((Path(work_dir) / "removed_results").glob("cycle_*/result_*.md")))
        packet = {
            "cycle": cycle,
            "workflow_mode": review_state.workflow_mode,
            "task_file": task_file,
            "summary_file": summary_file if summary_file and os.path.isfile(summary_file) else "",
            "results_dir": results_dir,
            "results_manifest_file": str(results_manifest_file),
            "result_status_snapshot_phase": "pre_result_review",
            "supporting_docs_dir": str(supporting_docs_dir),
            "supporting_docs_manifest_file": str(supporting_docs_manifest_file),
            "supporting_doc_count": len(supporting_docs_manifest),
            "previous_limitations_file": str(previous_limitations_file),
            "previous_limitations_source": previous_limitations_meta,
            "open_blockers_file": str(open_blockers_file),
            "open_blockers_snapshot_phase": "pre_review",
            "open_blockers_sync_note": open_blockers_note,
            "open_blocker_count": len(open_blockers),
            "passed_result_count": len(passed_results),
            "failed_result_count": len(failed_results),
            "pending_result_count": len(pending_results),
            "historical_removed_result_count": historical_removed_result_count,
        }
        review_packet_path = packet_dir / "global_review_packet.json"
        write_json(review_packet_path, packet)
        packet["review_packet_path"] = str(review_packet_path)
        return {
            "review_packet_path": str(review_packet_path),
            "summary_file": packet["summary_file"],
            "results_manifest_file": str(results_manifest_file),
            "supporting_docs_dir": str(supporting_docs_dir),
            "supporting_docs_manifest_file": str(supporting_docs_manifest_file),
            "previous_limitations_file": str(previous_limitations_file),
            "open_blockers_file": str(open_blockers_file),
        }

    def _write_blocker_snapshot(
        self,
        work_dir: str,
        cycle: int,
        review_state: ReviewState,
    ) -> None:
        snapshot_dir = Path(work_dir) / "_meta" / "blockers"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            snapshot_dir / f"cycle_{cycle:03d}.json",
            {
                "cycle": cycle,
                "workflow_mode": review_state.workflow_mode,
                "open_count": len(review_state.get_open_blockers()),
                "blockers": review_state.serialize_open_blockers(limit=review_state.MAX_OPEN_BLOCKERS),
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
    def _get_open_blockers_sync_note() -> str:
        return (
            "这是当前轮全局评审开始前的 blocker backlog 快照。该文件会在本轮评审返回后，"
            "根据你输出的 resolved_issues / blocking_issues 再同步更新。"
            "如果 summary 已经声称某个旧 blocker 本轮被关闭，但此快照里它仍显示 open，"
            "这通常只是正常的评审时序，不应单独作为“状态不一致” blocker；"
            "请直接核实证据，并把真正关闭的 blocker id 放入 resolved_issues。"
        )

    @staticmethod
    def _fallback_blockers(feedback: str) -> list[dict[str, str]]:
        text = (feedback or "").strip()
        if not text:
            text = "全局评审未通过，但未返回结构化 blocker"
        return [{
            "category": "global_review",
            "target": "summary_or_coverage",
            "severity": "high",
            "required_action": text[:400],
            "detail": text[:800],
            "status": "open",
        }]

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
        blocking_issues: list[dict] | None = None,
        resolved_issue_ids: list[str] | None = None,
        workflow_mode: str = "",
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
            blocking_issues=blocking_issues,
            resolved_issue_ids=resolved_issue_ids,
            workflow_mode=workflow_mode,
        )
