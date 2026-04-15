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

_FAIL_VERDICT_PATTERNS = [
    r"false[_ ]positive",
    r"insufficient[_ ]info",
    r"unverified",
    r"reject(?:ed)?",
    r"invalid",
    r"not[_ ]?pass(?:ed)?",
    r"false[_ ]alarm",
    r"证据不足",
    r"(?<!无)误报",
    r"驳回",
    r"不通过",
    r"未通过",
    r"不合格",
    r"漏洞不存在",
    r"需要修改",
    r"需要重做",
]

_PASS_VERDICT_PATTERNS = [
    r"true[_ ]positive",
    r"approve(?:d)?",
    r"accept(?:ed)?",
    r"valid",
    r"confirmed",
    r"verified",
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
]

_LOW_SIGNAL_SUMMARY_PATTERNS = [
    r"现在我.*生成.*json",
    r"现在我.*输出.*json",
    r"根据我.*分析.*现在我可以",
    r"让我.*完成.*评估",
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
    4. 最终兜底：默认通过（保持原框架的保守行为）
    """
    raw = (content or "").strip()

    try:
        json_result = _try_parse_json(raw)
        if json_result is not None:
            return json_result
        return _parse_by_keywords(raw)
    except Exception:
        detail = f"[评审响应解析失败，默认通过] {_one_line(raw)[:300]}"
        verdict = "PASS"
        return ParsedReviewResult(
            passed=True,
            verdict=verdict,
            feedback=_build_normalized_feedback(verdict, detail, True),
            feedback_detail=detail,
            raw_content=raw,
        )


def _try_parse_json(content: str) -> Optional[ParsedReviewResult]:
    """尝试从响应中提取 JSON"""
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

    seen = set()
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return _json_to_result(data, content)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue

    return None


def _json_to_result(data: dict[str, Any], raw: str) -> ParsedReviewResult:
    """将 JSON dict 转为 ParsedReviewResult"""
    passed = _extract_passed_from_json(data)
    if passed is None:
        passed = True

    detail_feedback = _extract_feedback_from_json(data)
    verdict_hint = _extract_verdict_text_from_json(data) or detail_feedback
    verdict = _normalize_verdict_label(verdict_hint, passed)

    if not detail_feedback:
        detail_feedback = verdict_hint if verdict_hint else raw

    scores = _extract_scores_from_json(data)
    confidence = _extract_confidence_from_json(data)

    return ParsedReviewResult(
        passed=bool(passed),
        verdict=verdict,
        feedback=_build_normalized_feedback(verdict, detail_feedback, bool(passed)),
        feedback_detail=detail_feedback,
        scores=scores,
        confidence=confidence,
        raw_content=raw,
    )


def _parse_by_keywords(content: str) -> ParsedReviewResult:
    """通过 verdict/关键词判断评审结果，并统一生成稳定字段。"""
    verdict_text = _extract_explicit_verdict(content)
    passed = None

    if verdict_text:
        passed = _classify_verdict_text(verdict_text)

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
        passed = True

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


def _extract_passed_from_json(data: dict[str, Any]) -> Optional[bool]:
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in ("passed", "pass", "approved", "accepted"):
                if key in node:
                    value = node[key]
                    if isinstance(value, bool):
                        return value
                    if isinstance(value, str):
                        verdict = _classify_verdict_text(value)
                        if verdict is not None:
                            return verdict
                        low = value.strip().lower()
                        if low in ("true", "yes", "y", "1"):
                            return True
                        if low in ("false", "no", "n", "0"):
                            return False

    verdict_text = _extract_verdict_text_from_json(data)
    if verdict_text:
        return _classify_verdict_text(verdict_text)

    feedback = _extract_feedback_from_json(data)
    if feedback:
        return _classify_verdict_text(feedback)

    return None


def _extract_feedback_from_json(data: dict[str, Any]) -> str:
    """提取尽量可读的详细反馈文本（稳定写入 feedback_detail）"""
    keys = (
        "feedback", "reason", "message", "summary", "conclusion",
        "details", "description", "recommendation", "overall_assessment",
        "overall_verdict", "assessment", "verification_summary",
        "verification_status",
    )
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in keys:
                value = node.get(key)
                rendered = _stringify_feedback_candidate(value)
                if rendered:
                    return rendered
    return ""


def _extract_verdict_text_from_json(data: dict[str, Any]) -> str:
    keys = (
        "verdict", "decision", "final_decision", "final_verdict",
        "overall_verdict", "review_conclusion", "action", "status",
        "recommendation", "verification_status",
    )
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in keys:
                value = node.get(key)
                if isinstance(value, str) and value.strip():
                    classified = _classify_verdict_text(value)
                    if classified is not None:
                        return value.strip()
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
    keys = ("confidence", "confidence_level")
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in keys:
                if key in node:
                    return _normalize_to_float(node[key])
    return 0.0


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
        r'(?:评审结论|最终判定|裁决|结论|verdict|overall_verdict|final_verdict)\s*[:：]\s*\**\s*([A-Za-z_ -]+)',
        r'\*\*\s*(FALSE_POSITIVE|TRUE_POSITIVE|INSUFFICIENT_INFO|REJECT|ACCEPT|APPROVED|UNVERIFIED|VALID|VERIFIED)\s*\*\*',
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

    if re.match(r'^false[_ ]positive\b', low) or (len(compact) <= 32 and compact.startswith("误报")):
        return "FALSE_POSITIVE"
    if re.match(r'^insufficient[_ ]info\b', low) or compact.startswith("证据不足"):
        return "INSUFFICIENT_INFO"
    if re.match(r'^unverified\b', low) or compact.startswith("未证实"):
        return "UNVERIFIED"
    if re.match(r'^reject(?:ed)?\b', low) or compact.startswith("驳回"):
        return "REJECT"
    if re.match(r'^invalid\b', low):
        return "INVALID"
    if re.match(r'^true[_ ]positive\b', low):
        return "TRUE_POSITIVE"
    if re.match(r'^confirmed\b', low):
        return "CONFIRMED"
    if re.match(r'^verified\b', low):
        return "VERIFIED"
    for pattern in _PARTIAL_VERDICT_PATTERNS:
        if (
            re.match(pattern, low, re.IGNORECASE)
            or compact.startswith("部分")
            or (len(compact) <= 80 and re.search(pattern, low, re.IGNORECASE))
        ):
            return "PARTIAL_PASS" if passed is not False else "PARTIAL_FAIL"
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
    if upper == "FALSE_POSITIVE":
        return "FALSE_POSITIVE（误报）"
    if upper == "INSUFFICIENT_INFO":
        return "INSUFFICIENT_INFO（证据不足）"
    if upper == "UNVERIFIED":
        return "UNVERIFIED（未证实）"
    if upper == "REJECT":
        return "REJECT（驳回）"
    if upper == "INVALID":
        return "INVALID（无效）"
    if upper == "TRUE_POSITIVE":
        return "TRUE_POSITIVE（有效发现）"
    if upper == "CONFIRMED":
        return "CONFIRMED（已确认）"
    if upper == "VERIFIED":
        return "VERIFIED（已验证）"
    if upper == "PARTIAL_PASS":
        return "PARTIAL_PASS（部分通过）"
    if upper == "PARTIAL_FAIL":
        return "PARTIAL_FAIL（部分不通过）"
    if upper == "FAIL":
        return "FAIL（未通过）"
    if upper == "PASS":
        return "PASS（通过）"

    v = verdict.strip()
    low = v.lower()
    if re.search(r'false[_ ]positive|误报', low):
        return "FALSE_POSITIVE（误报）"
    if re.search(r'insufficient[_ ]info|证据不足', low):
        return "INSUFFICIENT_INFO（证据不足）"
    if re.search(r'unverified', low):
        return "UNVERIFIED（未证实）"
    if re.search(r'reject|驳回', low):
        return "REJECT（驳回）"
    if re.search(r'invalid', low):
        return "INVALID（无效）"
    if re.search(r'true[_ ]positive', low):
        return "TRUE_POSITIVE（有效发现）"
    if re.search(r'approve|accept|valid|verified|通过|合格|成立', low):
        return "PASS（通过）"
    return _one_line(v)[:200]


def _one_line(text: str) -> str:
    return re.sub(r'\s+', ' ', (text or '')).strip()
