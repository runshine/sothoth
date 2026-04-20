"""
评审状态追踪

跨 cycle 追踪评审状态，支持 re_review_on_cycle 策略 (R6g)
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Any

from app.pi_vuln_core.utils.result_docs import list_result_report_files


@dataclass
class ResultItemState:
    """单个结果项的评审状态"""
    passed: bool = False
    last_reviewed_cycle: int = 0
    failure_reason: str = ""
    file_fingerprint: str = ""


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


@dataclass
class GlobalBlockerState:
    """全局评审阻塞项状态"""
    blocker_id: str
    category: str = ""
    target: str = ""
    severity: str = ""
    required_action: str = ""
    detail: str = ""
    status: str = "open"
    owner: str = "worker"
    actionable_by: str = "worker"
    first_seen_cycle: int = 0
    last_seen_cycle: int = 0
    seen_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.blocker_id,
            "category": self.category,
            "target": self.target,
            "severity": self.severity,
            "required_action": self.required_action,
            "detail": self.detail,
            "status": self.status,
            "owner": self.owner,
            "actionable_by": self.actionable_by,
            "first_seen_cycle": self.first_seen_cycle,
            "last_seen_cycle": self.last_seen_cycle,
            "seen_count": self.seen_count,
        }


def calculate_file_sha256(path: str) -> str:
    """计算文件内容 SHA256，用于检测 result 文件是否被修改。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def calculate_result_fingerprints(results_dir: str) -> dict[str, str]:
    """扫描 results/ 目录中所有漏洞报告文件，返回 filename -> sha256。"""
    if not os.path.isdir(results_dir):
        return {}

    fingerprints: dict[str, str] = {}
    for filename in list_result_report_files(results_dir):
        path = os.path.join(results_dir, filename)
        if os.path.isfile(path):
            fingerprints[filename] = calculate_file_sha256(path)
    return fingerprints


class ReviewState:
    """
    评审状态追踪器 (R6g, R6h)

    跨 cycle 记录：
    - 全局评审历史
    - 每个结果项的通过/失败状态
    - 结构化的失败反馈（区分全局 vs 结果，区分已通过 vs 待修改）
    - 已通过结果的文件指纹（文件内容变化则必须重审）
    - 全局评审 blocker backlog（稳定 ID，可跨轮延续）
    """

    MAX_OPEN_BLOCKERS = 10

    def __init__(self):
        self.global_review_history: list[GlobalReviewRecord] = []
        self.result_states: dict[str, ResultItemState] = {}
        # 结构化反馈 (不再是简单字符串拼接)
        self._global_feedbacks: list[dict] = []
        self._result_feedbacks: list[dict] = []

        # 全局 blocker backlog（单调、可审计）
        self.global_blockers: dict[str, GlobalBlockerState] = {}
        self.last_global_scores: dict[str, float] = {}
        self.last_global_feedback: str = ""

        # 工作模式：discovery -> closure
        self.workflow_mode: str = "discovery"
        self.closure_reason: str = ""
        self.closure_since_cycle: int | None = None

    def is_result_passed(
        self,
        result_filename: str,
        current_fingerprint: str | None = None,
    ) -> bool:
        state = self.result_states.get(result_filename)
        if state is None or not state.passed:
            return False

        # 若提供了当前指纹，则必须与上次通过时的指纹一致；否则视为“已变更，需要重审”
        if current_fingerprint is not None:
            return bool(state.file_fingerprint) and state.file_fingerprint == current_fingerprint
        return True

    def get_pending_results(
        self,
        all_results: list[str],
        advisors_config: list[dict],
        current_fingerprints: dict[str, str] | None = None,
    ) -> list[str]:
        any_rereview = any(
            a.get("re_review_on_cycle", False) for a in advisors_config)
        if any_rereview:
            return list(all_results)

        return [
            f for f in all_results
            if not self.is_result_passed(
                f,
                current_fingerprints.get(f) if current_fingerprints else None,
            )
        ]

    def mark_result_passed(
        self,
        result_filename: str,
        cycle: int,
        file_fingerprint: str = "",
    ) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=True,
            last_reviewed_cycle=cycle,
            file_fingerprint=file_fingerprint,
        )

    def mark_result_failed(
        self,
        result_filename: str,
        cycle: int,
        reason: str,
    ) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=False,
            last_reviewed_cycle=cycle,
            failure_reason=reason,
            file_fingerprint="",
        )

    def get_failed_results(
        self,
        current_results: list[str] | None = None,
    ) -> list[FailedResultItem]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            FailedResultItem(filename=name, reason=state.failure_reason)
            for name, state in self.result_states.items()
            if not state.passed and (current_set is None or name in current_set)
        ]

    def record_global_failure(self, cycle: int, feedback: str) -> None:
        self._global_feedbacks = [{
            "cycle": cycle, "feedback": feedback}]

    def record_result_failures(
        self,
        failed_items: list[FailedResultItem],
        cycle: int,
    ) -> None:
        for item in failed_items:
            self._result_feedbacks.append({
                "cycle": cycle,
                "filename": item.filename,
                "reason": item.reason})
            self.mark_result_failed(item.filename, cycle, item.reason)

    def has_failures(
        self,
        *,
        current_results: list[str] | None = None,
        actionable_by: str | None = None,
    ) -> bool:
        return bool(
            self.get_open_blockers(actionable_by=actionable_by)
            or self.get_failed_results(current_results=current_results)
        )

    def get_failed_result_filenames(
        self,
        current_results: list[str] | None = None,
    ) -> list[str]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            name for name, state in self.result_states.items()
            if not state.passed and (current_set is None or name in current_set)
        ]

    def get_passed_result_filenames(
        self,
        current_results: list[str] | None = None,
    ) -> list[str]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            name for name, state in self.result_states.items()
            if state.passed and (current_set is None or name in current_set)
        ]

    def activate_closure_mode(self, cycle: int, reason: str) -> None:
        self.workflow_mode = "closure"
        if self.closure_since_cycle is None:
            self.closure_since_cycle = cycle
        self.closure_reason = reason.strip()

    # ─────────────────────────────────────────────
    # Blocker backlog
    # ─────────────────────────────────────────────

    def record_global_review_result(
        self,
        *,
        cycle: int,
        passed: bool,
        feedback: str,
        scores: dict[str, float] | None = None,
        blocking_issues: list[dict[str, Any]] | None = None,
        resolved_issue_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self.last_global_scores = dict(scores or {})
        self.last_global_feedback = feedback or ""
        if passed:
            self._global_feedbacks = []
        return self.sync_global_blockers(
            cycle=cycle,
            blocking_issues=blocking_issues or [],
            resolved_issue_ids=resolved_issue_ids or [],
            passed=passed,
        )

    def sync_global_blockers(
        self,
        *,
        cycle: int,
        blocking_issues: list[dict[str, Any]],
        resolved_issue_ids: list[str],
        passed: bool,
    ) -> dict[str, Any]:
        resolved_ids = {
            self._normalize_blocker_id({"id": item_id})
            for item_id in (resolved_issue_ids or [])
            if str(item_id).strip()
        }

        normalized_current: list[dict[str, Any]] = []
        seen_current: set[str] = set()
        for raw_item in blocking_issues or []:
            normalized = self._normalize_blocker_payload(raw_item)
            if not normalized:
                continue
            blocker_id = normalized["id"]
            if blocker_id in seen_current:
                continue
            seen_current.add(blocker_id)
            normalized_current.append(normalized)

        opened: list[str] = []
        resolved: list[str] = []
        carried: list[str] = []
        truncated = 0

        if passed:
            for blocker in self.get_open_blockers():
                blocker.status = "resolved"
                blocker.last_seen_cycle = cycle
                resolved.append(blocker.blocker_id)
            return {
                "opened": opened,
                "resolved": resolved,
                "carried": carried,
                "truncated": truncated,
                "open_count": 0,
            }

        # 显式 resolved 的 blocker 优先关闭
        for blocker_id in sorted(resolved_ids):
            blocker = self.global_blockers.get(blocker_id)
            if blocker and blocker.status == "open":
                blocker.status = "resolved"
                blocker.last_seen_cycle = cycle
                resolved.append(blocker_id)

        open_count = len(self.get_open_blockers())

        for normalized in normalized_current:
            blocker_id = normalized["id"]
            existing = self.global_blockers.get(blocker_id)
            if existing is not None:
                was_open = existing.status == "open"
                existing.category = normalized["category"]
                existing.target = normalized["target"]
                existing.severity = normalized["severity"]
                existing.required_action = normalized["required_action"]
                existing.detail = normalized["detail"]
                existing.status = normalized["status"]
                existing.owner = normalized["owner"]
                existing.actionable_by = normalized["actionable_by"]
                existing.last_seen_cycle = cycle
                existing.seen_count += 1
                if existing.status != "open":
                    existing.status = "open"
                if not was_open:
                    open_count += 1
                    opened.append(blocker_id)
                continue

            if open_count >= self.MAX_OPEN_BLOCKERS:
                truncated += 1
                continue

            self.global_blockers[blocker_id] = GlobalBlockerState(
                blocker_id=blocker_id,
                category=normalized["category"],
                target=normalized["target"],
                severity=normalized["severity"],
                required_action=normalized["required_action"],
                detail=normalized["detail"],
                status="open",
                owner=normalized["owner"],
                actionable_by=normalized["actionable_by"],
                first_seen_cycle=cycle,
                last_seen_cycle=cycle,
                seen_count=1,
            )
            open_count += 1
            opened.append(blocker_id)

        current_ids = {item["id"] for item in normalized_current}
        for blocker in self.get_open_blockers():
            if blocker.blocker_id in resolved_ids or blocker.blocker_id in current_ids:
                continue
            carried.append(blocker.blocker_id)

        return {
            "opened": opened,
            "resolved": resolved,
            "carried": carried,
            "truncated": truncated,
            "open_count": len(self.get_open_blockers()),
        }

    def get_open_blockers(
        self,
        limit: int | None = None,
        actionable_by: str | None = None,
    ) -> list[GlobalBlockerState]:
        items = sorted(
            (
                item for item in self.global_blockers.values()
                if item.status == "open"
                and (actionable_by is None or item.actionable_by == actionable_by)
            ),
            key=lambda item: (item.first_seen_cycle, item.blocker_id),
        )
        if limit is not None:
            return items[:limit]
        return items

    def get_open_blocker_ids(
        self,
        limit: int | None = None,
        actionable_by: str | None = None,
    ) -> list[str]:
        return [
            item.blocker_id
            for item in self.get_open_blockers(limit=limit, actionable_by=actionable_by)
        ]

    def serialize_open_blockers(
        self,
        limit: int | None = None,
        actionable_by: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            item.to_dict()
            for item in self.get_open_blockers(limit=limit, actionable_by=actionable_by)
        ]

    def format_open_blockers(
        self,
        limit: int | None = None,
        actionable_by: str | None = None,
    ) -> str:
        blockers = self.get_open_blockers(limit=limit, actionable_by=actionable_by)
        if not blockers:
            if actionable_by == "worker":
                return "(当前无需要 Worker 处理的全局阻塞项)"
            if actionable_by == "framework":
                return "(当前无需要框架处理的全局阻塞项)"
            return "(当前无未关闭的全局阻塞项)"

        lines: list[str] = []
        for item in blockers:
            headline = f"- [{item.blocker_id}]"
            extras = []
            if item.category:
                extras.append(item.category)
            if item.target:
                extras.append(item.target)
            if item.severity:
                extras.append(item.severity)
            if extras:
                headline += " " + " / ".join(extras)
            lines.append(headline)
            if item.required_action:
                lines.append(f"  - required_action: {item.required_action}")
            if item.detail and item.detail != item.required_action:
                lines.append(f"  - detail: {item.detail}")
            lines.append(
                f"  - first_seen_cycle: {item.first_seen_cycle}, last_seen_cycle: {item.last_seen_cycle}, seen_count: {item.seen_count}")
        return "\n".join(lines)

    def format_failure_feedback(
        self,
        *,
        current_results: list[str] | None = None,
        include_open_blockers: bool = True,
        include_global_feedback_section: bool = True,
    ) -> str:
        """
        格式化为结构化反馈，让 Worker 清晰知道：
        1. 哪些结果已通过（不要修改）
        2. 哪些结果未通过 + 具体原因 + 改进方向
        3. 哪些全局 blocker 尚未关闭（不得静默删除）
        """
        sections = []

        # ═══ 工作模式 ═══
        mode_line = f"当前模式: {self.workflow_mode}"
        if self.workflow_mode == "closure" and self.closure_reason:
            mode_line += f"\n触发原因: {self.closure_reason}"
        sections.append(f"## 🧭 工作模式\n\n{mode_line}")

        # ═══ 已通过项（明确告知不要修改）═══
        passed = self.get_passed_result_filenames(current_results=current_results)
        if passed:
            sections.append(
                "## ✅ 已通过评审的结果（请勿修改）\n\n"
                + "\n".join(f"- {f}" for f in passed)
            )

        # ═══ 全局 blocker backlog ═══
        open_blockers = self.get_open_blockers(limit=self.MAX_OPEN_BLOCKERS)
        if include_open_blockers and open_blockers:
            sections.append(
                "## ❌ 尚未关闭的全局阻塞项（必须逐项处理，不得静默删除）\n\n"
                + self.format_open_blockers(limit=self.MAX_OPEN_BLOCKERS)
            )
        elif include_global_feedback_section and self._global_feedbacks:
            fb = self._global_feedbacks[-1]
            feedback_text = fb["feedback"]
            if len(feedback_text) > 1500:
                feedback_text = feedback_text[:1500] + "\n\n...(已截断，完整内容请查看 reviews/global/)"
            sections.append(
                f"## ❌ 最近一次全局评审反馈 (Cycle {fb['cycle']})\n\n{feedback_text}"
            )

        # ═══ 结果评审反馈（每个不通过项单独列出）═══
        failed = self.get_failed_results(current_results=current_results)
        if failed:
            lines = ["## ❌ 未通过评审的结果（需要修改或删除）\n"]
            lines.append("以下结果被评审员认为存在问题。请逐条处理：\n")
            for i, item in enumerate(failed, 1):
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
        action_lines = [
            "## 📋 你需要做的事",
            "",
            "1. **不要修改**已通过评审的结果文件",
            "2. 对每个未通过的结果，**重新阅读对应的反编译代码**，补充缺失的证据",
            "3. 如果确认是误报，**删除该结果文件**",
            "4. 如果能证实是真实漏洞，**重写该文件**，补充：函数偏移+代码片段+参数追溯+触发条件",
            "5. 更新 summary.md 反映修改",
            "6. 新的 summary.md 中，**不得遗漏上一轮“局限性与未覆盖区域”章节里已经声明的未覆盖项**；未解决则继续保留，已解决则明确说明如何闭环",
        ]
        if include_open_blockers and open_blockers:
            action_lines.extend([
                "7. 优先按 blocker backlog 收敛；未明确关闭的 blocker 默认仍然存在",
            ])
        if self.workflow_mode == "closure":
            action_lines.extend([
                "8. 当前处于 closure 模式：禁止无界扩张结果集；除非为关闭现有 blocker 所必需，否则不要新增新的扫描方向",
            ])
        sections.append("\n".join(action_lines))

        return "\n\n".join(sections)

    # ─────────────────────────────────────────────
    # Blocker 规范化
    # ─────────────────────────────────────────────

    @classmethod
    def _normalize_blocker_payload(cls, raw_item: Any) -> dict[str, str]:
        if isinstance(raw_item, str):
            text = raw_item.strip()
            if not text:
                return {}
            payload = {
                "id": "",
                "category": "global_review",
                "target": "",
                "severity": "high",
                "required_action": text,
                "detail": text,
                "status": "open",
                "owner": "worker",
                "actionable_by": "worker",
            }
            payload["id"] = cls._normalize_blocker_id(payload)
            return payload

        if not isinstance(raw_item, dict):
            return {}

        payload = {
            "id": str(raw_item.get("id") or raw_item.get("issue_id") or raw_item.get("blocker_id") or "").strip(),
            "category": str(raw_item.get("category") or raw_item.get("type") or "global_review").strip(),
            "target": str(raw_item.get("target") or raw_item.get("path") or raw_item.get("subject") or "").strip(),
            "severity": str(raw_item.get("severity") or raw_item.get("priority") or "high").strip(),
            "required_action": str(
                raw_item.get("required_action")
                or raw_item.get("action")
                or raw_item.get("recommendation")
                or raw_item.get("summary")
                or raw_item.get("detail")
                or raw_item.get("description")
                or ""
            ).strip(),
            "detail": str(
                raw_item.get("detail")
                or raw_item.get("description")
                or raw_item.get("summary")
                or raw_item.get("required_action")
                or raw_item.get("action")
                or ""
            ).strip(),
            "status": str(raw_item.get("status") or "open").strip() or "open",
            "owner": str(raw_item.get("owner") or raw_item.get("actionable_by") or "").strip(),
            "actionable_by": str(raw_item.get("actionable_by") or raw_item.get("owner") or "").strip(),
        }
        if not any(payload.values()):
            return {}
        owner = payload["owner"] or cls._infer_blocker_owner(payload)
        payload["owner"] = owner
        payload["actionable_by"] = payload["actionable_by"] or owner
        payload["id"] = cls._normalize_blocker_id(payload)
        return payload

    @staticmethod
    def _infer_blocker_owner(payload: dict[str, str]) -> str:
        text = " ".join(
            [
                payload.get("target", ""),
                payload.get("required_action", ""),
                payload.get("detail", ""),
            ]
        ).lower()
        framework_signals = (
            "open_blockers.json",
            "resolved_issues",
            "blocking_issues",
            "results_manifest",
            "global_review_packet",
            "review packet",
            "状态同步",
            "metadata",
            "failed_result_count",
            "passed=true",
            "passed=false",
        )
        if any(signal in text for signal in framework_signals):
            return "framework"
        return "worker"

    @classmethod
    def _normalize_blocker_id(cls, raw_item: Any) -> str:
        if isinstance(raw_item, dict):
            explicit = str(raw_item.get("id") or raw_item.get("issue_id") or raw_item.get("blocker_id") or "").strip()
            if explicit:
                return explicit
            basis = "|".join([
                str(raw_item.get("category") or raw_item.get("type") or "global_review").strip().lower(),
                str(raw_item.get("target") or raw_item.get("path") or raw_item.get("subject") or "").strip().lower(),
                str(raw_item.get("required_action") or raw_item.get("action") or raw_item.get("recommendation") or raw_item.get("summary") or raw_item.get("detail") or raw_item.get("description") or "").strip().lower(),
            ])
        else:
            basis = str(raw_item or "").strip().lower()

        basis = re.sub(r"\s+", " ", basis).strip()
        if not basis:
            basis = "global_review"
        digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10]

        if isinstance(raw_item, dict):
            category = str(raw_item.get("category") or raw_item.get("type") or "global_review").strip().lower() or "global_review"
            target = str(raw_item.get("target") or raw_item.get("path") or raw_item.get("subject") or "").strip().lower()
        else:
            category = "global_review"
            target = ""

        category_slug = re.sub(r"[^a-z0-9]+", "-", category).strip("-") or "global-review"
        target_slug = re.sub(r"[^a-z0-9]+", "-", target).strip("-")[:24]
        if target_slug:
            return f"{category_slug}:{target_slug}:{digest}"
        return f"{category_slug}:{digest}"
