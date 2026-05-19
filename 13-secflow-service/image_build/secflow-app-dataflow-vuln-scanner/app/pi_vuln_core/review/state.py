"""
评审状态追踪

跨 cycle 追踪评审状态，支持轻量反馈链。

设计原则：
  - Advisor 输出 passed/failed + scores + issues[]（结构化反馈）
  - 框架以 append-only 方式存储每轮评审记录
  - Worker 收到最近 N 轮的自然语言反馈
  - 框架只保留当前失败轮次的结构化 issue 作为轻量反馈
  - 通过/失败由 Advisor 判定，框架不做语义推断
  - 收敛检测参考 scores 趋势、产物变化和最近评审反馈
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any

from app.pi_vuln_core.utils.result_docs import list_result_report_files
from app.pi_vuln_core.utils.vulnerability_list import (
    STATUS_CONFIRMED,
    STATUS_FALSE_POSITIVE,
    STATUS_LABELS,
    STATUS_PENDING,
    TERMINAL_STATUSES,
)


@dataclass
class ResultItemState:
    """单个结果项的评审状态"""
    passed: bool = False
    last_reviewed_cycle: int = 0
    failure_reason: str = ""
    fingerprint: str = ""
    lifecycle_status: str = "candidate"
    active: bool = True
    vuln_status: str = STATUS_PENDING
    status_label: str = STATUS_LABELS[STATUS_PENDING]
    verdict: str = ""
    confidence: float = 0.0
    review_feedback: str = ""
    reviewed: bool = False


@dataclass
class GlobalReviewRecord:
    """单轮全局评审记录（append-only）"""
    advisor_id: str = ""
    cycle: int = 0
    passed: bool = False
    feedback: str = ""
    role_name: str = ""
    scores: dict[str, float] = field(default_factory=dict)
    issues: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FailedResultItem:
    filename: str
    reason: str
    cycle: int = 0


def calculate_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_result_fingerprints(results_dir: str) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    if not os.path.isdir(results_dir):
        return fingerprints
    for filename in list_result_report_files(results_dir):
        path = os.path.join(results_dir, filename)
        if os.path.isfile(path):
            fingerprints[filename] = calculate_file_sha256(path)
    return fingerprints


# 兼容别名
calculate_result_fingerprints = snapshot_result_fingerprints


class ReviewState:
    """
    评审状态追踪器

    跨 cycle 记录：
    - 全局评审历史（每轮每个参谋的 passed/scores/issues/feedback）
    - 每个结果项的通过/失败状态
    - 结构化的失败反馈
    - 已通过结果的文件指纹（文件内容变化则必须重审）
    """

    FEEDBACK_WINDOW = 2  # Worker 收到最近 N 轮反馈

    @staticmethod
    def prompt_safe_issue_id(value: object) -> str:
        """Return a model-facing issue id without leaking run-scope labels."""
        text = str(value or "").strip()
        if not text:
            return ""
        return re.sub(r"PROFILE-(?:fast|balanced|strict|audit)-", "SCOPE-", text, flags=re.IGNORECASE)

    @staticmethod
    def prompt_safe_blocking_type(value: object) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text.replace("profile_", "scope_")

    def __init__(self):
        self.global_review_history: list[GlobalReviewRecord] = []
        self.result_states: dict[str, ResultItemState] = {}
        self._global_feedbacks: list[dict] = []
        self._result_feedbacks: list[dict] = []

        self.last_global_scores: dict[str, float] = {}
        self.last_global_feedback: str = ""

        # 工作模式：discovery -> closure
        self.workflow_mode: str = "discovery"
        self.closure_reason: str = ""
        self.closure_since_cycle: int | None = None

    # ─────────────────────────────────────────────
    # 结果评审
    # ─────────────────────────────────────────────

    def is_result_passed(
        self,
        result_filename: str,
        current_fingerprint: str | None = None,
    ) -> bool:
        state = self.result_states.get(result_filename)
        if state is None or not state.passed:
            return False
        if current_fingerprint and state.fingerprint:
            return current_fingerprint == state.fingerprint
        return True

    def record_result_pass(
        self,
        result_filename: str,
        cycle: int,
        fingerprint: str = "",
    ) -> None:
        self.mark_result_confirmed(result_filename, cycle, fingerprint)

    def record_result_failure(
        self,
        result_filename: str,
        cycle: int,
        reason: str = "",
    ) -> None:
        self.mark_result_pending(
            result_filename,
            cycle,
            verdict="",
            feedback=reason,
        )

    def mark_result_inactive(
        self,
        result_filename: str,
        cycle: int,
        *,
        lifecycle_status: str,
        reason: str = "",
        fingerprint: str = "",
    ) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=False,
            last_reviewed_cycle=cycle,
            failure_reason=reason,
            fingerprint=fingerprint,
            lifecycle_status=lifecycle_status,
            active=False,
        )

    def record_result_failures(
        self,
        failed_items: list,
        cycle: int,
        *,
        file_fingerprints: dict[str, str] | None = None,
    ) -> None:
        fps = file_fingerprints or {}
        for item in failed_items:
            if isinstance(item, dict):
                filename = item.get("filename", "")
                reason = item.get("reason", "")
            else:
                filename = getattr(item, "filename", "")
                reason = getattr(item, "reason", "")
            if filename:
                self.record_result_failure(filename, cycle, reason)
                if fps.get(filename):
                    self.result_states[filename].fingerprint = fps[filename]
        self._result_feedbacks.append({
            "cycle": cycle,
            "failed_items": [
                {"filename": getattr(i, "filename", "") if not isinstance(i, dict) else i.get("filename", ""),
                 "reason": getattr(i, "reason", "") if not isinstance(i, dict) else i.get("reason", "")}
                for i in failed_items
            ],
        })

    def record_global_failure(self, cycle: int, feedback: str) -> None:
        self._global_feedbacks.append({
            "cycle": cycle,
            "feedback": feedback,
        })

    def get_failed_results(
        self,
        current_results: list[str] | None = None,
    ) -> list[FailedResultItem]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            FailedResultItem(
                filename=name,
                reason=state.failure_reason or state.review_feedback,
                cycle=state.last_reviewed_cycle,
            )
            for name, state in self.result_states.items()
            if (
                state.active
                and not state.passed
                and state.vuln_status not in {STATUS_FALSE_POSITIVE, STATUS_CONFIRMED}
                and bool(state.failure_reason)
                and (current_set is None or name in current_set)
            )
        ]

    def get_passed_result_filenames(
        self,
        current_results: list[str] | None = None,
    ) -> list[str]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            name for name, state in self.result_states.items()
            if state.passed and state.vuln_status == STATUS_CONFIRMED and (current_set is None or name in current_set)
        ]

    def activate_closure_mode(self, cycle: int, reason: str) -> None:
        self.workflow_mode = "closure"
        if self.closure_since_cycle is None:
            self.closure_since_cycle = cycle
        self.closure_reason = reason.strip()

    # ─────────────────────────────────────────────
    # 全局评审（轻量反馈链）
    # ─────────────────────────────────────────────

    def record_global_review_result(
        self,
        *,
        cycle: int,
        passed: bool,
        feedback: str,
        scores: dict[str, float] | None = None,
        issues: list[dict[str, Any]] | None = None,
        advisor_id: str = "",
        resolved_issue_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """记录一轮全局评审结果。

        issues 是参谋输出的结构化问题列表（无需跨轮 ID 追踪）。
        """
        effective_issues = issues or []
        self.last_global_scores = dict(scores or {})
        self.last_global_feedback = feedback or ""

        if passed:
            self._global_feedbacks = []
        elif feedback:
            entry = {
                "cycle": cycle,
                "feedback": feedback,
                "issues": [dict(item) for item in effective_issues],
            }
            if entry not in self._global_feedbacks:
                self._global_feedbacks.append(entry)

        return {
            "cycle": cycle,
            "passed": passed,
            "issue_count": len(effective_issues),
            "scores": dict(scores or {}),
        }

    # ─────────────────────────────────────────────
    # 轻量反馈链方法
    # ─────────────────────────────────────────────

    def get_recent_issues(self, last_n: int = 2) -> list[dict]:
        """返回最近 N 个失败 cycle 中所有未通过 advisor 的结构化问题。"""
        issues: list[dict] = []
        selected_cycles: set[int] = set()
        for record in reversed(self.global_review_history):
            if record.passed:
                continue
            if record.cycle not in selected_cycles:
                if len(selected_cycles) >= last_n:
                    break
                selected_cycles.add(record.cycle)
            for issue in record.issues:
                enriched = dict(issue)
                enriched.setdefault("cycle", record.cycle)
                if record.advisor_id:
                    enriched.setdefault("advisor_id", record.advisor_id)
                issues.append(enriched)
        return issues

    # ─────────────────────────────────────────────
    # 当前评审问题视图
    # ─────────────────────────────────────────────

    @staticmethod
    def _normalize_issue_text(value: Any, *, max_len: int) -> str:
        text = str(value or "").strip().lower()
        text = re.sub(r"`([^`]+)`", r"\1", text)
        text = re.sub(r"\bcycle\s*\d+\b", "cycle", text, flags=re.IGNORECASE)
        text = re.sub(r"\b第\s*\d+\s*轮\b", "本轮", text)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[\u200b-\u200f\ufeff]", "", text)
        return text[:max_len]

    @classmethod
    def _issue_semantic_key(cls, issue: dict[str, Any]) -> str:
        if not isinstance(issue, dict):
            issue = {"detail": str(issue)}
        parts = [
            issue.get("actionable_by") or issue.get("owner") or "worker",
            issue.get("category") or "global_review",
            issue.get("target") or issue.get("path") or issue.get("id") or issue.get("issue_id") or "",
            issue.get("required_action")
            or issue.get("detail")
            or issue.get("description")
            or issue.get("summary")
            or "",
        ]
        key = "|".join(
            cls._normalize_issue_text(part, max_len=160)
            for part in parts
            if str(part or "").strip()
        )
        return key or "global_review|unknown"

    @classmethod
    def _issue_entry_from_record(cls, issue: dict[str, Any], *, cycle: int, advisor_id: str = "") -> dict[str, Any]:
        item = dict(issue) if isinstance(issue, dict) else {"detail": str(issue)}
        if advisor_id:
            item.setdefault("advisor_id", advisor_id)
        semantic_key = cls._issue_semantic_key(item)
        digest = hashlib.sha1(semantic_key.encode("utf-8", errors="replace")).hexdigest()[:12]
        issue_id = str(item.get("id") or item.get("issue_id") or "").strip() or f"issue:{digest}"
        actionable_by = str(item.get("actionable_by") or item.get("owner") or "").strip()
        blocking_type = str(item.get("blocking_type") or item.get("blocker_type") or "").strip()
        acceptance = item.get("acceptance_criteria") or item.get("acceptance") or ""
        if isinstance(acceptance, list):
            acceptance = "; ".join(str(value).strip() for value in acceptance if str(value).strip())
        return {
            "signature": issue_id,
            "semantic_key": semantic_key,
            "first_seen_cycle": cycle,
            "last_seen_cycle": cycle,
            "seen_count": 1,
            "consecutive_count": 1,
            "issue": item,
            "issue_ids": [issue_id],
            "advisor_ids": [advisor_id] if advisor_id else [],
            "actionable_by": actionable_by,
            "blocking_type": blocking_type,
            "acceptance_criteria": str(acceptance).strip(),
        }

    def get_active_issue_entries(self, *, include_framework: bool = True) -> list[dict[str, Any]]:
        """Return current unresolved global-review blockers from recent feedback."""
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        latest_cycle = max((int(item.get("cycle") or 0) for item in self._global_feedbacks), default=0)
        for feedback in reversed(self._global_feedbacks):
            cycle = int(feedback.get("cycle") or 0)
            if latest_cycle and cycle != latest_cycle:
                continue
            for raw_issue in feedback.get("issues", []) or []:
                if not isinstance(raw_issue, dict):
                    continue
                entry = self._issue_entry_from_record(raw_issue, cycle=cycle, advisor_id=str(raw_issue.get("advisor_id") or ""))
                key = entry["semantic_key"]
                if key in seen:
                    continue
                seen.add(key)
                entries.append(entry)
        if not include_framework:
            entries = [
                entry for entry in entries
                if str(entry.get("actionable_by") or "").strip().lower() != "framework"
            ]
        entries.sort(key=lambda item: (-int(item.get("last_seen_cycle") or 0), str(item.get("signature") or "")))
        return entries

    def get_current_issue_records(self, *, include_framework: bool = True) -> list[dict[str, Any]]:
        """Return active unresolved issues in the UI/API-facing issue shape."""
        records: list[dict[str, Any]] = []
        for entry in self.get_active_issue_entries(include_framework=include_framework):
            issue = entry.get("issue") if isinstance(entry.get("issue"), dict) else {}
            record = dict(issue)
            issue_ids = [str(item).strip() for item in (entry.get("issue_ids") or []) if str(item).strip()]
            advisor_ids = [
                str(item).strip()
                for item in (entry.get("advisor_ids") or [])
                if str(item).strip()
            ]

            if not record.get("id"):
                record["id"] = issue_ids[0] if issue_ids else entry.get("signature") or ""
            record.setdefault("signature", entry.get("signature") or "")
            record.setdefault("semantic_key", entry.get("semantic_key") or "")
            record.setdefault("first_seen_cycle", entry.get("first_seen_cycle") or 0)
            record.setdefault("last_seen_cycle", entry.get("last_seen_cycle") or 0)
            record.setdefault("seen_count", entry.get("seen_count") or 0)
            record.setdefault("consecutive_count", entry.get("consecutive_count") or 0)
            if entry.get("actionable_by") and not record.get("actionable_by"):
                record["actionable_by"] = entry.get("actionable_by")
            if entry.get("blocking_type") and not record.get("blocking_type"):
                record["blocking_type"] = entry.get("blocking_type")
            if entry.get("acceptance_criteria") and not record.get("acceptance_criteria"):
                record["acceptance_criteria"] = entry.get("acceptance_criteria")
            if advisor_ids and not record.get("advisor_id"):
                record["advisor_id"] = ",".join(advisor_ids)
            records.append(record)
        return records

    def format_open_issue_backlog(
        self,
        *,
        max_items: int = 12,
        include_framework: bool = True,
    ) -> str:
        """Format current active issues as a closure backlog."""
        entries = self.get_active_issue_entries(include_framework=include_framework)
        if not entries:
            return "(当前没有 active global-review issue backlog)"
        lines = []
        for item in entries[:max_items]:
            issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
            detail = (
                issue.get("required_action")
                or issue.get("detail")
                or item.get("semantic_key")
                or ""
            )
            target = issue.get("target") or "(未指定 target)"
            issue_id = self.prompt_safe_issue_id(issue.get("id") or item.get("signature"))
            blocking_type = self.prompt_safe_blocking_type(item.get("blocking_type"))
            lines.append(
                f"- {issue_id}: target={target}; actionable_by={item.get('actionable_by') or 'worker'}; "
                f"blocking_type={blocking_type or 'unspecified'}; "
                f"last_seen=Cycle {item.get('last_seen_cycle')}; seen={item.get('seen_count')}"
            )
            if detail:
                lines.append(f"  required_action: {str(detail)[:300]}")
            acceptance = item.get("acceptance_criteria") or ""
            if acceptance:
                lines.append(f"  acceptance_criteria: {str(acceptance)[:260]}")
        if len(entries) > max_items:
            lines.append(f"- ... 另有 {len(entries) - max_items} 个 active issue，请参考最近的全局评审记录")
        return "\n".join(lines)

    def format_recent_feedback(self, last_n: int = 2) -> str:
        """格式化最近 N 轮的所有 advisor 反馈，供 Worker/Advisor 参考。"""
        sections: list[str] = []
        selected_cycle_set: set[int] = set()
        for record in reversed(self.global_review_history):
            if record.cycle in selected_cycle_set:
                continue
            if len(selected_cycle_set) >= last_n:
                break
            selected_cycle_set.add(record.cycle)

        for record in self.global_review_history:
            if record.cycle not in selected_cycle_set:
                continue
            status = "✅ PASS" if record.passed else "❌ FAIL"
            advisor = record.advisor_id or "global_review"
            header = f"### Cycle {record.cycle} — {advisor} ({status})"
            body = record.feedback.strip() or "(无反馈正文)"
            if record.scores:
                score_line = ", ".join(f"{k}={v:.2f}" for k, v in record.scores.items())
                body += f"\n分数: {score_line}"
            if record.issues:
                body += "\n问题:"
                for issue in record.issues[:5]:
                    detail = issue.get("detail") or issue.get("required_action") or str(issue)
                    body += f"\n- {str(detail)[:200]}"
            sections.append(f"{header}\n{body}")
        return "\n\n".join(sections)

    def format_failure_feedback(
        self,
        current_results: list[str] | None = None,
        **_kwargs,
    ) -> str:
        """构建失败反馈摘要（包含工作模式、已通过/失败结果、近期评审反馈）。"""
        sections: list[str] = []
        mode_line = f"当前模式：{self.workflow_mode}"
        if self.workflow_mode == "closure" and self.closure_reason:
            mode_line += f"\n触发原因：{self.closure_reason}"
        sections.append(f"## 🧭 工作模式\n\n{mode_line}")

        passed = self.get_passed_result_filenames(current_results=current_results)
        if passed:
            sections.append(
                "✅ 已通过评审的结果（请勿修改）\n\n"
                + "\n".join(f"- {f}" for f in passed)
            )

        failed = self.get_failed_results(current_results=current_results)
        if failed:
            lines = ["❌ 未通过评审的结果（需要修改或删除）\n"]
            for i, item in enumerate(failed, 1):
                reason_short = item.reason[:500]
                lines.append(f"{i}. {item.filename}: {reason_short}")
            sections.append("\n".join(lines))

        sections.append(
            "## 📋 行动指引\n\n"
            "1. 不要修改已通过评审的结果文件\n"
            "2. 对每个未通过的结果，重新阅读对应的反编译代码，补充缺失的证据\n"
            "3. 如果确认是误报，删除该结果文件\n"
            "4. 如需记录删除理由、补扫路径或证据矩阵，请写入 supporting_docs/；summary 阶段会统一整理 summary.md\n"
            "5. 不得遗漏上一轮局限性章节中已声明的未覆盖项"
        )
        return "\n\n".join(sections)

    # ─────────────────────────────────────────────
    # 其他查询方法
    # ─────────────────────────────────────────────

    def get_global_review_records(self, cycle: int | None = None) -> list[GlobalReviewRecord]:
        if cycle is None:
            return list(self.global_review_history)
        return [r for r in self.global_review_history if r.cycle == cycle]

    def get_failed_result_filenames(self, current_results: list[str] | None = None) -> list[str]:
        current_set = set(current_results or []) if current_results is not None else None
        return [
            name for name, state in self.result_states.items()
            if state.active and not state.passed and (current_set is None or name in current_set)
        ]

    def mark_result_confirmed(
        self,
        filename: str,
        cycle: int,
        fingerprint: str = "",
        verdict: str = "CONFIRMED",
        confidence: float = 0.0,
        feedback: str = "",
    ) -> None:
        self.result_states[filename] = ResultItemState(
            passed=True,
            last_reviewed_cycle=cycle,
            fingerprint=fingerprint,
            vuln_status=STATUS_CONFIRMED,
            status_label=STATUS_LABELS[STATUS_CONFIRMED],
            verdict="CONFIRMED",
            confidence=float(confidence or 0.0),
            review_feedback=feedback or "",
            reviewed=True,
        )

    def mark_result_false_positive(
        self,
        filename: str,
        cycle: int,
        fingerprint: str = "",
        verdict: str = "FALSE_POSITIVE",
        confidence: float = 0.0,
        feedback: str = "",
    ) -> None:
        self.result_states[filename] = ResultItemState(
            passed=False,
            last_reviewed_cycle=cycle,
            failure_reason="",
            fingerprint=fingerprint,
            vuln_status=STATUS_FALSE_POSITIVE,
            status_label=STATUS_LABELS[STATUS_FALSE_POSITIVE],
            verdict="FALSE_POSITIVE",
            confidence=float(confidence or 0.0),
            review_feedback=feedback or "",
            reviewed=True,
        )

    def mark_result_pending(
        self,
        filename: str,
        cycle: int,
        fingerprint: str = "",
        verdict: str = "",
        confidence: float = 0.0,
        feedback: str = "",
    ) -> None:
        self.result_states[filename] = ResultItemState(
            passed=False,
            last_reviewed_cycle=cycle,
            failure_reason=feedback or "",
            fingerprint=fingerprint,
            vuln_status=STATUS_PENDING,
            status_label=STATUS_LABELS[STATUS_PENDING],
            verdict="" if str(verdict or "").strip().upper() not in {"CONFIRMED", "FALSE_POSITIVE"} else str(verdict).strip().upper(),
            confidence=float(confidence or 0.0),
            review_feedback=feedback or "",
            reviewed=bool(verdict or feedback),
        )

    def mark_result_passed(self, filename: str, cycle: int, file_fingerprint: str = "") -> None:
        self.mark_result_confirmed(filename, cycle, file_fingerprint)

    def mark_result_failed(self, filename: str, cycle: int, reason: str = "", file_fingerprint: str = "") -> None:
        self.mark_result_pending(filename, cycle, file_fingerprint, "", feedback=reason)

    def is_result_failed(self, filename: str, current_fingerprint: str | None = None) -> bool:
        state = self.result_states.get(filename)
        if state is None or state.passed or not state.active or state.vuln_status in TERMINAL_STATUSES:
            return False
        if current_fingerprint and state.fingerprint and current_fingerprint != state.fingerprint:
            return False
        return bool(state.failure_reason)

    def is_result_terminal_reviewed(self, filename: str, current_fingerprint: str | None = None) -> bool:
        state = self.result_states.get(filename)
        if state is None or not state.active or state.vuln_status not in TERMINAL_STATUSES:
            return False
        if current_fingerprint and state.fingerprint:
            return current_fingerprint == state.fingerprint
        return True

    def get_result_files_by_status(self, status: str, current_results: list[str] | None = None) -> list[str]:
        current_set = set(current_results or []) if current_results is not None else None
        return sorted(
            name for name, state in self.result_states.items()
            if state.active and state.vuln_status == status and (current_set is None or name in current_set)
        )

    def get_result_status_counts(self, current_results: list[str] | None = None) -> dict[str, int]:
        counts = {"total": 0, STATUS_PENDING: 0, STATUS_CONFIRMED: 0, STATUS_FALSE_POSITIVE: 0, "inactive": 0}
        current_set = set(current_results or []) if current_results is not None else None
        for name, state in self.result_states.items():
            if current_set is not None and name not in current_set:
                continue
            counts["total"] += 1
            if not state.active:
                counts["inactive"] += 1
            counts[state.vuln_status] = counts.get(state.vuln_status, 0) + 1
        return counts

    def has_failures(
        self,
        *,
        current_results: list[str] | None = None,
        actionable_by: str | None = None,
    ) -> bool:
        """Check if there are failed results or unresolved global feedback.

        ``actionable_by`` narrows global issues to the actor that can act on
        them. Result item failures are worker-actionable because the worker must
        either fix or delete the report.
        """
        desired_owner = (actionable_by or "").strip().lower()
        failed = self.get_failed_results(current_results=current_results)
        if failed and not desired_owner:
            return True

        recent_issues = self.get_recent_issues(last_n=self.FEEDBACK_WINDOW)
        if desired_owner:
            if any(self._issue_matches_owner(issue, desired_owner) for issue in recent_issues):
                return True
            active_issues = [
                entry.get("issue") or {}
                for entry in self.get_active_issue_entries()
                if isinstance(entry.get("issue"), dict)
            ]
            if any(self._issue_matches_owner(issue, desired_owner) for issue in active_issues):
                return True
            if recent_issues:
                return False
            fallback_issues = [
                issue
                for feedback in self._global_feedbacks
                for issue in feedback.get("issues", [])
                if isinstance(issue, dict)
            ]
            if fallback_issues:
                return any(
                    self._issue_matches_owner(issue, desired_owner)
                    for issue in fallback_issues
                )
            # 无结构化 issue 的全局失败仍按 worker 可执行返工处理。
            return desired_owner == "worker" and bool(self._global_feedbacks)

        if self._global_feedbacks:
            return True
        if any(not record.passed for record in self.global_review_history):
            return True
        return False

    @staticmethod
    def _issue_matches_owner(issue: dict[str, Any], desired_owner: str) -> bool:
        explicit_owner = str(
            issue.get("actionable_by") or issue.get("owner") or ""
        ).strip().lower()
        category = str(issue.get("category") or "").strip().lower()

        if explicit_owner:
            return explicit_owner == desired_owner

        if desired_owner != "worker":
            return False

        non_worker_categories = {
            "framework",
            "schema_contract",
            "metadata",
            "metadata_sync",
            "summary",
        }
        return category not in non_worker_categories

    def is_result_review_stable(self) -> bool:
        active_states = [state for state in self.result_states.values() if state.active]
        return bool(self.result_states) and all(state.vuln_status in TERMINAL_STATUSES for state in active_states)

    def get_pending_results(
        self,
        current_results: list[str] | None = None,
        advisors_dicts: list[dict] | None = None,
        current_fingerprints: dict[str, str] | None = None,
    ) -> list[str]:
        """返回需要（重新）评审的结果文件列表。

        跳过规则：
        - 已通过且指纹未变 → 跳过
        - 已失败且指纹未变 → 跳过（沿用上轮失败结论）
        """
        current_set = set(current_results or [])
        fps = current_fingerprints or {}
        pending = []
        for name in current_set:
            state = self.result_states.get(name)
            if state is None:
                pending.append(name)
                continue
            current_fp = fps.get(name, "")
            old_fp = state.fingerprint or ""
            if old_fp and current_fp and old_fp == current_fp:
                if state.vuln_status in TERMINAL_STATUSES:
                    continue  # 指纹未变且已有终态，跳过
                if state.vuln_status == STATUS_PENDING and state.reviewed:
                    continue  # 证据不足等非终态但未变化，避免重复提交
            if not old_fp and not current_fp:
                if state.vuln_status in TERMINAL_STATUSES:
                    continue  # 无指纹但已有终态，跳过
            pending.append(name)
        return sorted(pending)
