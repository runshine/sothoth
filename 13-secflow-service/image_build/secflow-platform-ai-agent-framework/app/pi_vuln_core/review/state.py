"""
评审状态追踪

跨 cycle 追踪评审状态，支持 re_review_on_cycle 策略 (R6g)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResultItemState:
    """单个结果项的评审状态"""
    passed: bool = False
    last_reviewed_cycle: int = 0
    failure_reason: str = ""


@dataclass
class GlobalReviewRecord:
    """全局评审记录条目"""
    cycle: int
    advisor_id: str
    passed: bool
    feedback: str = ""


@dataclass
class FailedResultItem:
    """评审不通过的结果项"""
    filename: str
    reason: str


class ReviewState:
    """
    评审状态追踪器 (R6g, R6h)

    跨 cycle 记录：
    - 全局评审历史
    - 每个结果项的通过/失败状态
    - 结构化的失败反馈（区分全局 vs 结果，区分已通过 vs 待修改）
    """

    def __init__(self):
        self.global_review_history: list[GlobalReviewRecord] = []
        self.result_states: dict[str, ResultItemState] = {}
        # 结构化反馈 (不再是简单字符串拼接)
        self._global_feedbacks: list[dict] = []
        self._result_feedbacks: list[dict] = []

    def is_result_passed(self, result_filename: str) -> bool:
        state = self.result_states.get(result_filename)
        return state is not None and state.passed

    def get_pending_results(
        self, all_results: list[str], advisors_config: list[dict],
    ) -> list[str]:
        any_rereview = any(
            a.get("re_review_on_cycle", False) for a in advisors_config)
        if any_rereview:
            return list(all_results)
        return [f for f in all_results if not self.is_result_passed(f)]

    def mark_result_passed(self, result_filename: str, cycle: int) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=True, last_reviewed_cycle=cycle)

    def mark_result_failed(self, result_filename: str, cycle: int,
                            reason: str) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=False, last_reviewed_cycle=cycle, failure_reason=reason)

    def get_failed_results(self) -> list[FailedResultItem]:
        return [
            FailedResultItem(filename=name, reason=state.failure_reason)
            for name, state in self.result_states.items()
            if not state.passed
        ]

    def record_global_failure(self, cycle: int, feedback: str) -> None:
        self._global_feedbacks.append({
            "cycle": cycle, "feedback": feedback})

    def record_result_failures(self, failed_items: list[FailedResultItem],
                                cycle: int) -> None:
        for item in failed_items:
            self._result_feedbacks.append({
                "cycle": cycle,
                "filename": item.filename,
                "reason": item.reason})
            self.mark_result_failed(item.filename, cycle, item.reason)

    def has_failures(self) -> bool:
        return bool(self._global_feedbacks or self._result_feedbacks)

    def get_failed_result_filenames(self) -> list[str]:
        return [name for name, state in self.result_states.items()
                if not state.passed]

    def get_passed_result_filenames(self) -> list[str]:
        return [name for name, state in self.result_states.items()
                if state.passed]

    def format_failure_feedback(self) -> str:
        """
        格式化为结构化反馈，让 Worker 清晰知道：
        1. 哪些结果已通过（不要修改）
        2. 哪些结果未通过 + 具体原因 + 改进方向
        3. 全局评审的宏观意见
        """
        sections = []

        # ═══ 已通过项（明确告知不要修改）═══
        passed = self.get_passed_result_filenames()
        if passed:
            sections.append(
                "## ✅ 已通过评审的结果（请勿修改）\n\n"
                + "\n".join(f"- {f}" for f in passed)
            )

        # ═══ 全局评审反馈 ═══
        if self._global_feedbacks:
            fb = self._global_feedbacks[-1]  # 最近一次
            sections.append(
                f"## ❌ 全局评审反馈 (Cycle {fb['cycle']})\n\n"
                f"评审员认为整体报告存在以下问题，请针对性改进：\n\n"
                f"{fb['feedback']}"
            )

        # ═══ 结果评审反馈（每个不通过项单独列出）═══
        failed = self.get_failed_results()
        if failed:
            lines = ["## ❌ 未通过评审的结果（需要修改或删除）\n"]
            lines.append("以下结果被评审员认为存在问题。请逐条处理：\n")
            for i, item in enumerate(failed, 1):
                # 截取前500字，避免过长
                reason_short = item.reason[:500]
                if len(item.reason) > 500:
                    reason_short += "..."
                lines.append(
                    f"### {i}. {item.filename}\n"
                    f"**问题**: {reason_short}\n"
                    f"**要求**: 请重新分析该漏洞，补充证据或确认为误报后删除该文件。\n"
                )
            sections.append("\n".join(lines))

        # ═══ 行动指引 ═══
        sections.append(
            "## 📋 你需要做的事\n\n"
            "1. **不要修改**已通过评审的结果文件\n"
            "2. 对每个未通过的结果，**重新阅读对应的反编译代码**，补充缺失的证据\n"
            "3. 如果确认是误报，**删除该结果文件**\n"
            "4. 如果能证实是真实漏洞，**重写该文件**，补充：函数偏移+代码片段+参数追溯+触发条件\n"
            "5. 更新 summary.md 反映修改\n"
        )

        return "\n\n".join(sections)
