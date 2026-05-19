"""
评审结果解析工具

解析智能体评审响应，提取通过/不通过及反馈内容。
重点目标：
- 兼容 JSON / Markdown / 混合格式
- 兼容 verdict / decision / overall_verdict 等多种字段名
- 兼容 confidence/scores 使用 HIGH/MEDIUM/LOW 等字符串枚举
- 统一输出稳定字段：verdict / feedback / feedback_detail / raw_content
- 解析失败时绝不抛异常，避免污染评审主流程
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ParsedReviewResult:
    """解析后的评审结果"""
    passed: bool
    verdict: str = ""
    feedback: str = ""
    feedback_detail: str = ""
    scores: dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    raw_content: str = ""
    issues: list[dict[str, Any]] = field(default_factory=list)
    resolved_issue_ids: list[str] = field(default_factory=list)


@dataclass
class _VerdictSignal:
    passed: Optional[bool] = None
    verdict_text: str = ""


_CONFIDENCE_MAP = {
    "definitive": 0.98,
    "very_high": 0.95,
    "high": 0.85,
    "medium": 0.60,
    "moderate": 0.60,
    "low": 0.30,
    "very_low": 0.10,
    "partial": 0.50,
    "partial_pass": 0.55,
    "partial_fail": 0.35,
    "accurate": 0.85,
    "positive": 0.80,
    "minor": 0.40,
    "major": 0.25,
    "critical": 0.10,
    "invalid": 0.10,
}

_JSON_VERDICT_KEYS = (
    "verdict",
    "decision",
    "final_decision",
    "final_verdict",
    "overall_verdict",
    "review_conclusion",
    "action",
    "status",
    "verification_status",
    "verification_result",
    "validation_result",
    "review_result",
    "assessment_result",
)

_JSON_FEEDBACK_KEYS = (
    "feedback",
    "reason",
    "message",
    "summary",
    "conclusion",
    "details",
    "description",
    "overall_assessment",
    "assessment",
    "verification_summary",
    "overall_verdict",
    "review_conclusion",
    "rationale",
    "justification",
    "reasoning",
    "recommendation",
    "notes",
)

_JSON_CONFIDENCE_KEYS = ("confidence", "confidence_level")

_JSON_BOOLEAN_HINT_KEYS = (
    "is_false_positive",
    "false_positive",
    "is_vulnerability_real",
    "vulnerability_confirmed",
    "vulnerability_exists",
    "severity_correct",
    "is_severity_accurate",
    "attack_scenario_invalid",
    "data_flow_claim_incorrect",
    "attack_path_valid",
    "attack_path_reachable",
)

_FAIL_VERDICT_PATTERNS = [
    r"partial(?:ly)?[_ -]?(?:valid|pass(?:ed)?|verified|confirmed|true[_ -]?positive)",
    r"confirmed[_ -]?with[_ -]?modifications?",
    r"confirm(?:ed)?[_ -]?with[_ -]?reduced[_ -]?severity",
    r"close[_ -]?as[_ -]?false[_ -]?positive",
    r"部分(?:通过|成立|有效|正确)",
    r"false[_ -]?(?:positive|alarm)",
    r"insufficient[_ ]info",
    r"unverified",
    r"reject(?:ed)?",
    r"refut(?:e|ed)",
    r"dismiss(?:ed)?",
    r"invalid",
    r"not[_ ]?pass(?:ed)?",
    r"not[_ ]?(?:achievable|exploitable|valid)",
    r"not a vulnerability",
    r"\bfail(?:ed)?\b",
    r"证据不足",
    r"(?<!无)(?<!非)(?<!不是)误报",
    r"(?<!非)(?<!不是)假阳性",
    r"驳回",
    r"不通过",
    r"未通过",
    r"不合格",
    r"漏洞不存在",
    r"不可利用",
    r"不可达",
    r"不成立",
    r"需要修改",
    r"需要重做",
    r"需要返工",
    r"需要重写",
]

_PASS_VERDICT_PATTERNS = [
    r"\btrue[_ ]positive\b",
    r"\bapprove(?:d)?\b",
    r"\baccept(?:ed)?\b",
    r"\bvalid\b",
    r"\bconfirmed\b",
    r"\bverified\b",
    r"\bpass(?:ed)?\b",
    r"通过",
    r"合格",
    r"成立",
    r"无误报",
]

_PARTIAL_VERDICT_PATTERNS = [
    r"partial",
    r"部分",
    r"caveat",
    r"保留",
    r"有条件",
    r"不充分",
    r"confirmed[_ -]?with[_ -]?modifications?",
    r"confirm(?:ed)?[_ -]?with[_ -]?reduced[_ -]?severity",
]

_LOW_SIGNAL_SUMMARY_PATTERNS = [
    r"现在我.*生成.*json",
    r"现在我.*输出.*json",
    r"根据我.*分析.*现在我可以",
    r"让我.*完成.*评估",
    r"基于.*现在.*生成.*json",
    r"根据.*现在.*输出.*json",
    r"评审完成",
    r"以下是.*评审结果",
]


def parse_review_response(content: str) -> ParsedReviewResult:
    """
    解析评审智能体的响应内容。

    支持多种格式：
    1. JSON 格式（含多种 verdict/feedback 字段）
    2. Markdown/纯文本格式（提取结论行）
    3. 关键词检测
    4. 最终兜底：默认不通过（fail-close，避免误放行）
    """
    original = content or ""
    raw = original.strip()

    try:
        if not raw:
            return _default_fail_result(original, "评审智能体返回空响应，按不通过处理")
        json_result = _try_parse_json(original)
        if json_result is not None:
            return json_result
        return _parse_by_keywords(original)
    except Exception:
        detail = f"[评审响应解析失败，默认不通过] {_one_line(raw)[:300]}"
        return _default_fail_result(original, detail)


def _try_parse_json(content: str) -> Optional[ParsedReviewResult]:
    """尝试从响应中提取 JSON / JSON-like 内容。"""
    if not content:
        return None

    candidates: list[str] = [content]

    json_match = re.search(r'```json\s*\n?(.*?)\n?```', content, re.DOTALL)
    if json_match:
        candidates.append(json_match.group(1).strip())

    first_brace = content.find("{")
    last_brace = content.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidates.append(content[first_brace:last_brace + 1])

    unique_candidates: list[str] = []
    seen = set()
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        unique_candidates.append(candidate)

    for candidate in unique_candidates:
        for variant in (candidate, _repair_json_like_candidate(candidate)):
            variant = variant.strip()
            if not variant:
                continue
            try:
                data = json.loads(variant)
                if isinstance(data, dict):
                    return _json_to_result(data, content)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

    for candidate in unique_candidates:
        pseudo = _extract_pseudo_json_fields(candidate)
        if pseudo:
            return _json_to_result(pseudo, content)

    return None


def _json_to_result(data: dict[str, Any], raw: str) -> ParsedReviewResult:
    """将 JSON dict 转为 ParsedReviewResult。"""
    scores = _extract_scores_from_json(data)
    confidence = _extract_confidence_from_json(data)
    issues = _extract_issues_from_json(data)
    resolved_issue_ids = _extract_resolved_issue_ids_from_json(data)

    passed = _extract_passed_from_json(data)
    verdict_signal = _infer_verdict_from_json(data)
    detail_feedback = _extract_feedback_from_json(data)
    explicit_verdict = verdict_signal.verdict_text or _extract_verdict_text_from_json(data)
    classified_verdict = verdict_signal.passed

    if passed is None:
        if classified_verdict is not None:
            passed = classified_verdict
        elif detail_feedback:
            passed = _classify_verdict_text(detail_feedback)
    elif classified_verdict is not None and classified_verdict != passed:
        passed = False

    if passed is None:
        detail = detail_feedback or explicit_verdict or "评审 JSON 缺少明确 passed/verdict，按不通过处理"
        verdict_hint = explicit_verdict or "FAIL"
        return _default_fail_result(
            raw,
            detail,
            verdict=_normalize_verdict_label(verdict_hint, False),
            scores=scores,
            confidence=confidence,
            issues=issues,
            resolved_issue_ids=resolved_issue_ids,
        )

    verdict_hint = explicit_verdict or ("PASS" if passed else "FAIL")
    verdict = _normalize_verdict_label(verdict_hint, passed)

    if not detail_feedback:
        detail_feedback = explicit_verdict if explicit_verdict else raw

    return ParsedReviewResult(
        passed=bool(passed),
        verdict=verdict,
        feedback=_build_normalized_feedback(verdict, detail_feedback, bool(passed)),
        feedback_detail=detail_feedback,
        scores=scores,
        confidence=confidence,
        raw_content=raw,
        issues=issues,
        resolved_issue_ids=resolved_issue_ids,
    )


def _parse_by_keywords(content: str) -> ParsedReviewResult:
    """通过 verdict/关键词判断评审结果，并统一生成稳定字段。"""
    verdict_text = _extract_explicit_verdict(content)
    passed = None

    if verdict_text:
        passed = _signal_from_verdict_text(verdict_text).passed

    if passed is None:
        lower = content.lower()
        for pattern in _FAIL_VERDICT_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                passed = False
                break

    if passed is None:
        lower = content.lower()
        for pattern in _PASS_VERDICT_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                passed = True
                break

    if passed is None:
        return _default_fail_result(
            content,
            "评审响应未包含明确可判定的通过/不通过信号，按不通过处理",
        )

    verdict = _normalize_verdict_label(verdict_text or content, passed)
    return ParsedReviewResult(
        passed=passed,
        verdict=verdict,
        feedback=_build_normalized_feedback(verdict, content, passed),
        feedback_detail=content,
        raw_content=content,
    )


def _walk_values(obj: Any):
    """递归遍历 JSON 中的所有值"""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_values(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_values(item)


def _repair_json_like_candidate(candidate: str) -> str:
    repaired = candidate or ""
    def _fix_range_value(m: re.Match) -> str:
        cleaned = re.sub(r'\s+', '', m.group(2))
        return f'{m.group(1)}"{cleaned}"{m.group(3)}'
    repaired = re.sub(
        r'(:\s*)(\d+\s*-\s*\d+)(\s*[,}\]])',
        _fix_range_value,
        repaired,
    )
    repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
    return repaired


def _extract_pseudo_json_fields(candidate: str) -> dict[str, Any]:
    pseudo: dict[str, Any] = {}

    for key in ("passed", "pass", "approved", "accepted"):
        bool_value = _extract_bool_field_from_text(candidate, key)
        if bool_value is not None:
            pseudo[key] = bool_value
            break
        text_value = _extract_quoted_text_field(candidate, (key,))
        if text_value:
            pseudo[key] = text_value
            break

    for key in _JSON_VERDICT_KEYS + _JSON_FEEDBACK_KEYS + _JSON_CONFIDENCE_KEYS:
        if key in pseudo:
            continue
        text_value = _extract_quoted_text_field(candidate, (key,))
        if text_value:
            pseudo[key] = text_value

    for key in _JSON_BOOLEAN_HINT_KEYS:
        bool_value = _extract_bool_field_from_text(candidate, key)
        if bool_value is not None:
            pseudo[key] = bool_value

    return pseudo


def _extract_quoted_text_field(text: str, keys: tuple[str, ...]) -> str:
    for key in keys:
        pattern = rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"'
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        raw_value = match.group(1)
        try:
            decoded = json.loads(f'"{raw_value}"')
        except json.JSONDecodeError:
            decoded = raw_value.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
        if isinstance(decoded, str) and decoded.strip():
            return decoded.strip()
    return ""


def _extract_bool_field_from_text(text: str, key: str) -> Optional[bool]:
    match = re.search(
        rf'"{re.escape(key)}"\s*:\s*(true|false)',
        text,
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1).strip().lower() == "true"


def _coerce_bool_like_text(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    low = value.strip().lower()
    if low in {"true", "yes", "y", "1"}:
        return True
    if low in {"false", "no", "n", "0"}:
        return False
    return None


def _signal_from_verdict_text(value: Any) -> _VerdictSignal:
    if not isinstance(value, str) or not value.strip():
        return _VerdictSignal()

    stripped = value.strip()
    bool_like = _coerce_bool_like_text(stripped)
    if bool_like is True:
        return _VerdictSignal(True, "CONFIRMED")
    if bool_like is False:
        return _VerdictSignal(False, "FALSE_POSITIVE")

    passed = _classify_verdict_text(stripped)
    if passed is None:
        return _VerdictSignal()
    return _VerdictSignal(passed, stripped)


def _find_bool_in_json(data: dict[str, Any], keys: tuple[str, ...]) -> Optional[bool]:
    for node in _walk_values(data):
        if not isinstance(node, dict):
            continue
        for key in keys:
            if key not in node:
                continue
            bool_value = _coerce_bool_like_text(node.get(key))
            if bool_value is not None:
                return bool_value
    return None


def _infer_verdict_from_json(data: dict[str, Any]) -> _VerdictSignal:
    for key in _JSON_VERDICT_KEYS:
        signal = _signal_from_verdict_text(data.get(key))
        if signal.passed is not None:
            return signal

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _JSON_VERDICT_KEYS:
            signal = _signal_from_verdict_text(node.get(key))
            if signal.passed is not None:
                return signal

    false_positive = _find_bool_in_json(data, ("is_false_positive", "false_positive"))
    if false_positive is True:
        return _VerdictSignal(False, "FALSE_POSITIVE")

    vulnerability_real = _find_bool_in_json(
        data,
        ("is_vulnerability_real", "vulnerability_confirmed", "vulnerability_exists"),
    )
    severity_correct = _find_bool_in_json(data, ("is_severity_accurate", "severity_correct"))
    attack_invalid = _find_bool_in_json(data, ("attack_scenario_invalid", "data_flow_claim_incorrect"))
    attack_path_valid = _find_bool_in_json(data, ("attack_path_valid", "attack_path_reachable"))

    if vulnerability_real is False:
        return _VerdictSignal(False, "FALSE_POSITIVE")
    if vulnerability_real is True:
        if severity_correct is False or attack_invalid is True or attack_path_valid is False:
            return _VerdictSignal(False, "REJECTED")
        return _VerdictSignal(True, "CONFIRMED")

    return _VerdictSignal()


def _extract_passed_from_json(data: dict[str, Any]) -> Optional[bool]:
    for key in ("passed", "pass", "approved", "accepted"):
        if key not in data:
            continue
        value = data[key]
        bool_like = _coerce_bool_like_text(value)
        if bool_like is not None:
            return bool_like
        if isinstance(value, str):
            verdict = _classify_verdict_text(value)
            if verdict is not None:
                return verdict

    return None


def _extract_feedback_from_json(data: dict[str, Any]) -> str:
    """提取尽量可读的详细反馈文本（稳定写入 feedback_detail）。"""
    for key in _JSON_FEEDBACK_KEYS:
        rendered = _stringify_feedback_candidate(data.get(key))
        if rendered:
            return rendered

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _JSON_FEEDBACK_KEYS:
            rendered = _stringify_feedback_candidate(node.get(key))
            if rendered:
                return rendered
    return ""


def _extract_verdict_text_from_json(data: dict[str, Any]) -> str:
    for key in _JSON_VERDICT_KEYS:
        signal = _signal_from_verdict_text(data.get(key))
        if signal.verdict_text:
            return signal.verdict_text

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _JSON_VERDICT_KEYS:
            signal = _signal_from_verdict_text(node.get(key))
            if signal.verdict_text:
                return signal.verdict_text
    return ""


def _extract_scores_from_json(data: dict[str, Any]) -> dict[str, float]:
    for node in _walk_values(data):
        if isinstance(node, dict) and "scores" in node and isinstance(node["scores"], dict):
            result: dict[str, float] = {}
            for k, v in node["scores"].items():
                result[str(k)] = _normalize_to_float(v)
            return result
    return {}


def _extract_confidence_from_json(data: dict[str, Any]) -> float:
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in _JSON_CONFIDENCE_KEYS:
                if key in node:
                    return _normalize_to_float(node[key])
    return 0.0


def _extract_issues_from_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    keys = ("issues",)
    for node in _walk_values(data):
        if not isinstance(node, dict):
            continue
        for key in keys:
            value = node.get(key)
            if isinstance(value, list):
                issues: list[dict[str, Any]] = []
                for item in value:
                    normalized = _normalize_issue(item)
                    if normalized:
                        issues.append(normalized)
                if issues:
                    return issues
    return []


def _extract_resolved_issue_ids_from_json(data: dict[str, Any]) -> list[str]:
    keys = (
        "resolved_issues",
        "resolved_issue_ids",
        "resolvedIssues",
        "resolvedIssueIds",
    )
    for node in _walk_values(data):
        if not isinstance(node, dict):
            continue
        for key in keys:
            value = node.get(key)
            if isinstance(value, list):
                seen: list[str] = []
                for item in value:
                    if isinstance(item, str) and item.strip():
                        seen.append(item.strip())
                    elif isinstance(item, dict):
                        item_id = str(
                            item.get("id")
                            or item.get("issue_id")
                            or ""
                        ).strip()
                        if item_id:
                            seen.append(item_id)
                if seen:
                    return seen
    return []


def _normalize_issue(item: Any) -> dict[str, Any]:
    if isinstance(item, str):
        text = item.strip()
        if not text:
            return {}
        return {
            "id": "",
            "category": "global_review",
            "target": "",
            "severity": "high",
            "required_action": text,
            "detail": text,
        }

    if not isinstance(item, dict):
        return {}

    issue_id = str(
        item.get("id")
        or item.get("issue_id")
        or item.get("key")
        or ""
    ).strip()
    category = str(item.get("category") or item.get("type") or "").strip()
    target = str(item.get("target") or item.get("path") or item.get("subject") or "").strip()
    severity = str(item.get("severity") or item.get("priority") or "").strip()
    required_action = str(
        item.get("required_action")
        or item.get("action")
        or item.get("recommendation")
        or item.get("summary")
        or item.get("detail")
        or item.get("description")
        or ""
    ).strip()
    detail = str(
        item.get("detail")
        or item.get("description")
        or item.get("summary")
        or required_action
    ).strip()
    owner = str(item.get("owner") or "").strip()
    actionable_by = str(
        item.get("actionable_by")
        or item.get("actionableBy")
        or item.get("action_owner")
        or item.get("owner")
        or ""
    ).strip()
    source = str(item.get("source") or "").strip()
    blocking_type = str(
        item.get("blocking_type")
        or item.get("blocker_type")
        or item.get("blockingType")
        or item.get("blockerType")
        or item.get("blocker")
        or ""
    ).strip()
    acceptance_criteria = (
        item.get("acceptance_criteria")
        or item.get("acceptanceCriteria")
        or item.get("acceptance")
        or ""
    )
    if isinstance(acceptance_criteria, list):
        acceptance_criteria = "; ".join(
            str(part).strip()
            for part in acceptance_criteria
            if str(part).strip()
        )
    else:
        acceptance_criteria = str(acceptance_criteria or "").strip()
    external_dependency = str(
        item.get("external_dependency")
        or item.get("externalDependency")
        or ""
    ).strip()
    if not any([issue_id, category, target, required_action, detail, owner, actionable_by]):
        return {}

    normalized = {
        "id": issue_id,
        "category": category,
        "target": target,
        "severity": severity,
        "required_action": required_action,
        "detail": detail,
    }
    if owner:
        normalized["owner"] = owner
    if actionable_by:
        normalized["actionable_by"] = actionable_by
    if source:
        normalized["source"] = source
    if blocking_type:
        normalized["blocking_type"] = blocking_type
    if acceptance_criteria:
        normalized["acceptance_criteria"] = acceptance_criteria
    if external_dependency:
        normalized["external_dependency"] = external_dependency
    return normalized


def _normalize_to_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if not text:
            return 0.0
        if text in _CONFIDENCE_MAP:
            return _CONFIDENCE_MAP[text]
        ratio = re.match(r'^(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)$', text)
        if ratio:
            num = float(ratio.group(1))
            den = float(ratio.group(2))
            return (num / den) if den else 0.0
        try:
            return float(text)
        except ValueError:
            return 0.0
    return 0.0


def _extract_explicit_verdict(content: str) -> str:
    if not content:
        return ""
    patterns = [
        r'(?:评审结论|最终判定|裁决|结论|verdict|overall_verdict|final_verdict|verification_result|verification_status)\s*[:：]\s*\**\s*([A-Za-z_ -]+)',
        r'\*\*\s*(FALSE_POSITIVE|TRUE_POSITIVE|INSUFFICIENT_INFO|REJECT|REJECTED|REFUTED|DISMISS|DISMISSED|ACCEPT|APPROVED|UNVERIFIED|VALID|VERIFIED|CONFIRMED|PARTIALLY_VALID|CONFIRMED_WITH_MODIFICATIONS)\s*\*\*',
    ]
    for pattern in patterns:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _classify_verdict_text(text: str) -> Optional[bool]:
    if not text:
        return None
    lower = text.lower()

    for pattern in _FAIL_VERDICT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return False
    for pattern in _PASS_VERDICT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return True
    return None


def _normalize_verdict_label(text: str, passed: Optional[bool]) -> str:
    compact = _one_line(text)
    low = compact.lower()

    if re.search(
        r'false(?:[_ ]positive)?|close[_ -]?as[_ -]?false[_ -]?positive|(?<!非)(?<!不是)误报|(?<!非)(?<!不是)假阳性',
        low,
    ):
        return "FALSE_POSITIVE"
    if re.match(r'^insufficient[_ ]info\b', low) or compact.startswith("证据不足"):
        return "INSUFFICIENT_INFO"
    if re.match(r'^unverified\b', low) or compact.startswith("未证实"):
        return "INSUFFICIENT_INFO"
    if re.match(r'^reject(?:ed)?\b', low) or compact.startswith("驳回"):
        return "REJECTED"
    if re.match(r'^refut(?:e|ed)\b', low):
        return "REJECTED"
    if re.match(r'^dismiss(?:ed)?\b', low):
        return "REJECTED"
    if re.match(r'^invalid\b', low):
        return "REJECTED"
    if re.match(r'^true[_ ]positive\b', low):
        return "CONFIRMED"
    if re.match(r'^confirmed\b', low):
        return "CONFIRMED"
    if re.match(r'^verified\b', low):
        return "CONFIRMED"
    for pattern in _PARTIAL_VERDICT_PATTERNS:
        if (
            re.match(pattern, low, re.IGNORECASE)
            or compact.startswith("部分")
            or (len(compact) <= 80 and re.search(pattern, low, re.IGNORECASE))
        ):
            return "REJECTED"
    if re.match(r'^(approve|approved|accept|accepted|valid)\b', low) or compact.startswith(("通过", "合格", "成立")):
        return "PASS"
    if passed is False:
        return "FAIL"
    return "PASS"


def _build_normalized_feedback(verdict: str, detail: str, passed: bool) -> str:
    verdict_label = verdict or ("PASS" if passed else "FAIL")
    verdict_summary = _format_verdict_summary(verdict_label) or verdict_label
    detail_summary = _extract_feedback_summary(detail)
    if not detail_summary:
        return verdict_summary

    stripped = re.sub(
        rf'^{re.escape(verdict_label)}\s*[-:：]\s*',
        '',
        detail_summary,
        flags=re.IGNORECASE,
    ).strip()
    if stripped != detail_summary and stripped:
        return f"{verdict_summary} - {stripped}"[:300]
    if detail_summary == verdict_summary:
        return verdict_summary
    if detail_summary.upper() == verdict_label:
        return verdict_summary
    return f"{verdict_summary} - {detail_summary}"[:300]


def _default_fail_result(
    raw: str,
    detail: str,
    *,
    verdict: str = "FAIL",
    scores: dict[str, float] | None = None,
    confidence: float = 0.0,
    issues: list[dict[str, Any]] | None = None,
    resolved_issue_ids: list[str] | None = None,
) -> ParsedReviewResult:
    return ParsedReviewResult(
        passed=False,
        verdict=verdict,
        feedback=_build_normalized_feedback(verdict, detail, False),
        feedback_detail=detail,
        scores=dict(scores or {}),
        confidence=confidence,
        raw_content=raw,
        issues=list(issues or []),
        resolved_issue_ids=list(resolved_issue_ids or []),
    )


def _extract_feedback_summary(text: str) -> str:
    if not text:
        return ""

    explicit = _extract_explicit_verdict(text)
    if explicit and len(_one_line(text)) < 120:
        return _format_verdict_summary(explicit)

    cleaned = _strip_think_blocks(text)
    in_code_block = False
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if line.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue
        candidate = re.sub(r'^[#>*\-\d.\s]+', '', line).strip()
        if not candidate:
            continue
        if any(re.search(p, candidate, re.IGNORECASE) for p in _LOW_SIGNAL_SUMMARY_PATTERNS):
            continue
        if _looks_like_structural_line(candidate):
            continue
        return _one_line(candidate)[:220]

    if explicit:
        return _format_verdict_summary(explicit)
    return ""


def _strip_think_blocks(text: str) -> str:
    text = re.sub(r'<think>.*?</think>', ' ', text, flags=re.IGNORECASE | re.DOTALL)
    return text.strip()


def _looks_like_structural_line(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped in {"{", "}", "[", "]", "(", ")"}:
        return True
    if stripped.startswith(("{", "}", "[", "]")):
        return True
    if re.match(r'^["\'\[{].*[}\]",]$', stripped):
        return True
    if re.match(r'^[A-Za-z0-9_]+\s*[:=]\s*[\[{"\']', stripped):
        return True
    return False


def _stringify_feedback_candidate(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        items = [str(item).strip() for item in value if isinstance(item, str) and str(item).strip()]
        if items:
            return "\n".join(items)
    return ""


def _format_verdict_summary(verdict: str) -> str:
    if not verdict:
        return ""
    upper = verdict.strip().upper()
    if upper in {"FALSE", "FALSE_POSITIVE", "CLOSE_AS_FALSE_POSITIVE"}:
        return "FALSE_POSITIVE（误报）"
    if upper == "INSUFFICIENT_INFO":
        return "INSUFFICIENT_INFO（证据不足）"
    if upper == "UNVERIFIED":
        return "INSUFFICIENT_INFO（证据不足）"
    if upper in {
        "REJECT",
        "REJECTED",
        "INVALID",
        "REFUTED",
        "DISMISS",
        "DISMISSED",
        "PARTIAL_PASS",
        "PARTIAL_FAIL",
        "PARTIALLY_VALID",
        "CONFIRMED_WITH_MODIFICATIONS",
        "CONFIRM_WITH_REDUCED_SEVERITY",
    }:
        return "REJECTED（驳回）"
    if upper == "TRUE_POSITIVE":
        return "CONFIRMED（已确认）"
    if upper == "CONFIRMED":
        return "CONFIRMED（已确认）"
    if upper == "VERIFIED":
        return "CONFIRMED（已确认）"
    if upper == "FAIL":
        return "FAIL（未通过）"
    if upper == "PASS":
        return "PASS（通过）"

    v = verdict.strip()
    low = v.lower()
    if re.search(r'false(?:[_ ]positive)?|close[_ -]?as[_ -]?false[_ -]?positive|误报|假阳性', low):
        return "FALSE_POSITIVE（误报）"
    if re.search(r'insufficient[_ ]info|证据不足', low):
        return "INSUFFICIENT_INFO（证据不足）"
    if re.search(r'unverified', low):
        return "INSUFFICIENT_INFO（证据不足）"
    if re.search(r'reject|驳回', low):
        return "REJECTED（驳回）"
    if re.search(r'refut(?:e|ed)', low):
        return "REJECTED（驳回）"
    if re.search(r'dismiss(?:ed)?', low):
        return "REJECTED（驳回）"
    if re.search(r'invalid', low):
        return "REJECTED（驳回）"
    if re.search(r'partial(?:ly)?[_ -]?(?:valid|pass(?:ed)?|verified|confirmed|true[_ -]?positive)|confirmed[_ -]?with[_ -]?modifications?|confirm(?:ed)?[_ -]?with[_ -]?reduced[_ -]?severity|部分(?:通过|成立|有效|正确)', low):
        return "REJECTED（驳回）"
    if re.search(r'true[_ ]positive', low):
        return "CONFIRMED（已确认）"
    if re.search(r'approve|accept|\bvalid\b|verified|通过|合格|成立', low):
        return "PASS（通过）"
    return _one_line(v)[:200]


def _one_line(text: str) -> str:
    return re.sub(r'\s+', ' ', (text or '')).strip()
