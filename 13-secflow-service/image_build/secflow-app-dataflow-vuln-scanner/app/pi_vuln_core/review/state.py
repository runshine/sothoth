"""
评审状态追踪

跨 cycle 追踪评审状态，支持轻量反馈链与 issue ledger。

设计原则：
  - Advisor 输出 passed/failed + scores + issues[]（结构化反馈）
  - 框架以 append-only 方式存储每轮评审记录
  - Worker 收到最近 N 轮的自然语言反馈
  - 框架用 issue 指纹检测重复阻塞项，避免评审循环空转
  - 通过/失败由 Advisor 判定，框架不做语义推断
  - 收敛检测同时参考 scores 趋势、产物变化和 issue ledger
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any

from app.pi_vuln_core.utils.result_docs import list_result_report_files


@dataclass
class ResultItemState:
    """单个结果项的评审状态"""
    passed: bool = False
    last_reviewed_cycle: int = 0
    failure_reason: str = ""
    fingerprint: str = ""
    lifecycle_status: str = "candidate"
    active: bool = True


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


@dataclass
class IssueLedgerEntry:
    """跨 cycle 跟踪的全局评审阻塞项。"""
    signature: str
    semantic_key: str
    first_seen_cycle: int
    last_seen_cycle: int
    seen_count: int = 0
    consecutive_count: int = 0
    cycles: list[int] = field(default_factory=list)
    issue: dict[str, Any] = field(default_factory=dict)
    issue_ids: list[str] = field(default_factory=list)
    advisor_ids: list[str] = field(default_factory=list)
    actionable_by: str = ""
    blocking_type: str = ""
    acceptance_criteria: str = ""
    active: bool = True
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "semantic_key": self.semantic_key,
            "first_seen_cycle": self.first_seen_cycle,
            "last_seen_cycle": self.last_seen_cycle,
            "seen_count": self.seen_count,
            "consecutive_count": self.consecutive_count,
            "cycles": list(self.cycles),
            "issue_ids": list(self.issue_ids),
            "advisor_ids": list(self.advisor_ids),
            "actionable_by": self.actionable_by,
            "blocking_type": self.blocking_type,
            "acceptance_criteria": self.acceptance_criteria,
            "active": self.active,
            "resolved": self.resolved,
            "issue": dict(self.issue),
        }


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

        # issue ledger：按语义指纹追踪重复问题，供 plateau / closure 决策使用。
        self.issue_ledger: dict[str, IssueLedgerEntry] = {}
        self._last_issue_signatures: set[str] = set()
        self.last_issue_ledger_status: dict[str, Any] = {
            "current_issue_count": 0,
            "active_issue_count": 0,
            "current_signatures": [],
            "current_semantic_keys": [],
            "repeated_signatures": [],
            "max_consecutive_count": 0,
            "max_seen_count": 0,
            "dominant_issue": None,
        }

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
        self.result_states[result_filename] = ResultItemState(
            passed=True,
            last_reviewed_cycle=cycle,
            fingerprint=fingerprint,
        )

    def record_result_failure(
        self,
        result_filename: str,
        cycle: int,
        reason: str = "",
    ) -> None:
        self.result_states[result_filename] = ResultItemState(
            passed=False,
            last_reviewed_cycle=cycle,
            failure_reason=reason,
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
                reason=state.failure_reason,
                cycle=state.last_reviewed_cycle,
            )
            for name, state in self.result_states.items()
            if state.active and not state.passed and (current_set is None or name in current_set)
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

        if passed and not resolved_issue_ids:
            resolved_issue_ids = []
            for entry in self.issue_ledger.values():
                if entry.active and not entry.resolved:
                    resolved_issue_ids.extend(entry.issue_ids)
                    resolved_issue_ids.append(entry.signature)

        self.update_issue_ledger(
            cycle=cycle,
            issues=[] if passed else effective_issues,
            resolved_issue_ids=resolved_issue_ids,
        )

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
    # issue ledger / 收敛辅助
    # ─────────────────────────────────────────────

    @classmethod
    def issue_signature(cls, issue: dict[str, Any]) -> tuple[str, str]:
        """返回稳定 issue 指纹与可读语义 key。

        Advisor 的 issue id 可能跨轮漂移，因此指纹优先使用
        actionable/category/target/detail/required_action 的规范化组合。
        """
        if not isinstance(issue, dict):
            issue = {"detail": str(issue)}

        actionable = cls._normalize_issue_text(
            issue.get("actionable_by") or issue.get("owner") or "worker",
            max_len=40,
        )
        category = cls._normalize_issue_text(issue.get("category") or "global_review", max_len=60)
        target = cls._normalize_issue_text(issue.get("target") or issue.get("path") or "", max_len=120)
        detail = cls._normalize_issue_text(
            issue.get("required_action")
            or issue.get("detail")
            or issue.get("description")
            or issue.get("summary")
            or issue.get("id")
            or "",
            max_len=220,
        )
        fallback_id = cls._normalize_issue_id(str(issue.get("id") or issue.get("issue_id") or ""))
        semantic_key = "|".join(
            part for part in (actionable, category, target or fallback_id, detail) if part
        )
        if not semantic_key:
            semantic_key = "global_review|unknown"
        digest = hashlib.sha1(semantic_key.encode("utf-8", errors="replace")).hexdigest()[:16]
        return f"issue:{digest}", semantic_key

    @staticmethod
    def _normalize_issue_id(value: str) -> str:
        text = (value or "").strip().lower()
        text = re.sub(r"^(cmp|dpt|global[-_]?review|global[-_]?completeness|global[-_]?depth)[-_:]+", "", text)
        return re.sub(r"[^a-z0-9_.:/-]+", "-", text)[:120]

    @staticmethod
    def _normalize_issue_text(value: Any, *, max_len: int) -> str:
        text = str(value or "").strip().lower()
        text = re.sub(r"`([^`]+)`", r"\1", text)
        text = re.sub(r"\bcycle\s*\d+\b", "cycle", text, flags=re.IGNORECASE)
        text = re.sub(r"\b第\s*\d+\s*轮\b", "本轮", text)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[\u200b-\u200f\ufeff]", "", text)
        return text[:max_len]

    def update_issue_ledger(
        self,
        *,
        cycle: int,
        issues: list[dict[str, Any]] | None = None,
        resolved_issue_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        current_signatures: set[str] = set()
        current_entries: list[IssueLedgerEntry] = []
        resolved_ids = {
            str(item).strip()
            for item in (resolved_issue_ids or [])
            if str(item).strip()
        }

        for raw_issue in issues or []:
            issue = dict(raw_issue) if isinstance(raw_issue, dict) else {"detail": str(raw_issue)}
            signature, semantic_key = self.issue_signature(issue)
            current_signatures.add(signature)

            entry = self.issue_ledger.get(signature)
            if entry is None:
                entry = IssueLedgerEntry(
                    signature=signature,
                    semantic_key=semantic_key,
                    first_seen_cycle=cycle,
                    last_seen_cycle=0,
                )
                self.issue_ledger[signature] = entry

            if entry.last_seen_cycle != cycle:
                entry.seen_count += 1
                entry.consecutive_count = (
                    entry.consecutive_count + 1
                    if signature in self._last_issue_signatures else
                    1
                )
                entry.cycles.append(cycle)

            entry.last_seen_cycle = cycle
            entry.issue = issue
            entry.semantic_key = semantic_key
            entry.active = True
            entry.resolved = False
            entry.actionable_by = str(issue.get("actionable_by") or issue.get("owner") or "").strip()
            entry.blocking_type = str(issue.get("blocking_type") or issue.get("blocker_type") or "").strip()
            acceptance = issue.get("acceptance_criteria") or issue.get("acceptance") or ""
            if isinstance(acceptance, list):
                acceptance = "; ".join(str(item).strip() for item in acceptance if str(item).strip())
            entry.acceptance_criteria = str(acceptance).strip()
            self._append_unique(entry.issue_ids, str(issue.get("id") or issue.get("issue_id") or "").strip())
            self._append_unique(entry.advisor_ids, str(issue.get("advisor_id") or issue.get("source") or "").strip())
            current_entries.append(entry)

        for signature, entry in self.issue_ledger.items():
            if signature not in current_signatures and entry.last_seen_cycle < cycle:
                entry.active = False
                entry.consecutive_count = 0
            if self._entry_resolved(entry, resolved_ids):
                entry.active = False
                entry.resolved = True
                entry.consecutive_count = 0

        self._last_issue_signatures = current_signatures
        self.last_issue_ledger_status = self._build_issue_ledger_status(current_entries)
        return dict(self.last_issue_ledger_status)

    def rebuild_issue_ledger_from_history(self) -> dict[str, Any]:
        """从 append-only 全局评审记录重建 issue ledger（用于 resume）。"""
        self.issue_ledger = {}
        self._last_issue_signatures = set()
        self.last_issue_ledger_status = {
            "current_issue_count": 0,
            "active_issue_count": 0,
            "current_signatures": [],
            "current_semantic_keys": [],
            "repeated_signatures": [],
            "max_consecutive_count": 0,
            "max_seen_count": 0,
            "dominant_issue": None,
        }
        cycles = sorted({record.cycle for record in self.global_review_history})
        for cycle in cycles:
            issues: list[dict[str, Any]] = []
            for record in self.global_review_history:
                if record.cycle != cycle or record.passed:
                    continue
                for issue in record.issues:
                    enriched = dict(issue)
                    if record.advisor_id:
                        enriched.setdefault("advisor_id", record.advisor_id)
                    issues.append(enriched)
            self.update_issue_ledger(cycle=cycle, issues=issues)
        return dict(self.last_issue_ledger_status)

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        if value and value not in items:
            items.append(value)

    @staticmethod
    def _entry_resolved(entry: IssueLedgerEntry, resolved_ids: set[str]) -> bool:
        if not resolved_ids:
            return False
        candidates = {entry.signature, entry.semantic_key}
        candidates.update(item for item in entry.issue_ids if item)
        normalized_resolved = {ReviewState._normalize_issue_id(item) for item in resolved_ids}
        normalized_candidates = {ReviewState._normalize_issue_id(item) for item in candidates}
        return bool(candidates & resolved_ids or normalized_candidates & normalized_resolved)

    def _build_issue_ledger_status(
        self,
        current_entries: list[IssueLedgerEntry],
    ) -> dict[str, Any]:
        active_entries = [entry for entry in self.issue_ledger.values() if entry.active]
        dominant = max(
            current_entries or active_entries,
            key=lambda item: (item.consecutive_count, item.seen_count, item.last_seen_cycle),
            default=None,
        )
        repeated = [
            entry.signature
            for entry in current_entries
            if entry.consecutive_count >= 2
        ]
        return {
            "current_issue_count": len(current_entries),
            "active_issue_count": len(active_entries),
            "current_signatures": [entry.signature for entry in current_entries],
            "current_semantic_keys": [entry.semantic_key for entry in current_entries],
            "repeated_signatures": repeated,
            "max_consecutive_count": max(
                (entry.consecutive_count for entry in current_entries),
                default=0,
            ),
            "max_seen_count": max(
                (entry.seen_count for entry in current_entries),
                default=0,
            ),
            "dominant_issue": dominant.to_dict() if dominant else None,
        }

    def get_issue_ledger_status(self) -> dict[str, Any]:
        return dict(self.last_issue_ledger_status)

    def get_issue_ledger_snapshot(self) -> dict[str, Any]:
        entries = sorted(
            (entry.to_dict() for entry in self.issue_ledger.values()),
            key=lambda item: (
                not bool(item.get("active")),
                -int(item.get("last_seen_cycle") or 0),
                str(item.get("signature") or ""),
            ),
        )
        return {
            "schema_version": 1,
            "workflow_mode": self.workflow_mode,
            "closure_since_cycle": self.closure_since_cycle,
            "closure_reason": self.closure_reason,
            "last_status": self.get_issue_ledger_status(),
            "entries": entries,
        }

    def format_issue_ledger_summary(
        self,
        *,
        min_consecutive: int = 2,
        max_items: int = 5,
    ) -> str:
        entries = [
            entry for entry in self.issue_ledger.values()
            if entry.active and entry.consecutive_count >= min_consecutive
        ]
        entries.sort(key=lambda item: (-item.consecutive_count, -item.last_seen_cycle, item.signature))
        if not entries:
            return ""
        lines = []
        for entry in entries[:max_items]:
            detail = (
                entry.issue.get("required_action")
                or entry.issue.get("detail")
                or entry.semantic_key
            )
            target = entry.issue.get("target") or "(未指定 target)"
            safe_signature = self.prompt_safe_issue_id(entry.signature)
            safe_blocking_type = self.prompt_safe_blocking_type(entry.blocking_type)
            lines.append(
                f"- {safe_signature}: 连续 {entry.consecutive_count} 轮，target={target}，"
                f"actionable_by={entry.actionable_by or 'worker'}，blocking_type={safe_blocking_type or 'unspecified'}，"
                f"要求={str(detail)[:220]}"
            )
            if entry.acceptance_criteria:
                lines.append(f"  acceptance_criteria: {entry.acceptance_criteria[:220]}")
        return "\n".join(lines)

    def get_active_issue_entries(self, *, include_framework: bool = True) -> list[dict[str, Any]]:
        """Return all active unresolved global-review blockers."""
        entries = [
            entry for entry in self.issue_ledger.values()
            if entry.active and not entry.resolved
        ]
        if not include_framework:
            entries = [
                entry for entry in entries
                if (entry.actionable_by or "").strip().lower() != "framework"
            ]
        entries.sort(key=lambda item: (-item.last_seen_cycle, -item.seen_count, item.signature))
        return [entry.to_dict() for entry in entries]

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
        """Format active issue ledger entries as a closure backlog."""
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
            lines.append(f"- ... 另有 {len(entries) - max_items} 个 active issue，详见 `_meta/issue_ledger.json`")
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

    def mark_result_passed(self, filename: str, cycle: int, file_fingerprint: str = "") -> None:
        self.result_states[filename] = ResultItemState(
            passed=True, last_reviewed_cycle=cycle, fingerprint=file_fingerprint,
        )

    def mark_result_failed(self, filename: str, cycle: int, reason: str = "", file_fingerprint: str = "") -> None:
        self.result_states[filename] = ResultItemState(
            passed=False, last_reviewed_cycle=cycle, failure_reason=reason, fingerprint=file_fingerprint,
        )

    def is_result_failed(self, filename: str, current_fingerprint: str | None = None) -> bool:
        state = self.result_states.get(filename)
        if state is None or state.passed or not state.active:
            return False
        if current_fingerprint and state.fingerprint and current_fingerprint != state.fingerprint:
            return False
        return True

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
        if failed and (not desired_owner or desired_owner == "worker"):
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
            "ledger",
            "summary",
        }
        return category not in non_worker_categories

    def is_result_review_stable(self) -> bool:
        active_states = [state for state in self.result_states.values() if state.active]
        return bool(self.result_states) and all(state.passed for state in active_states)

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
                continue  # 指纹未变，跳过
            if not old_fp and not current_fp:
                if state.passed:
                    continue  # 无指纹但已通过，跳过
            pending.append(name)
        return sorted(pending)
