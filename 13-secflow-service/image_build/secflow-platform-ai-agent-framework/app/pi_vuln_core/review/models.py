"""
评审结果解析工具

解析智能体评审响应，提取通过/不通过及反馈内容。
重点目标：
- 兼容 JSON / Markdown / 混合格式
- 兼容 verdict / decision / overall_verdict 等多种字段名
- 兼容 confidence/scores 使用 HIGH/MEDIUM/LOW 等字符串枚举
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
    feedback: str = ""
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
    r"误报",
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
        # 解析器本身不应影响主流程
        return ParsedReviewResult(
            passed=True,
            feedback=f"[评审响应解析失败，默认通过] {_one_line(raw)[:300]}",
            raw_content=raw,
        )


def _try_parse_json(content: str) -> Optional[ParsedReviewResult]:
    """尝试从响应中提取 JSON"""
    if not content:
        return None

    candidates: list[str] = [content]

    # 尝试提取 ```json ... ``` 代码块
    json_match = re.search(r'```json\s*\n?(.*?)\n?```', content, re.DOTALL)
    if json_match:
        candidates.append(json_match.group(1).strip())

    # 尝试提取首个 { 到末个 } 的大对象
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

    # feedback 存完整内容（用于持久化记录），日志截断由 visual_log 负责
    feedback = _extract_feedback_from_json(data)
    if not feedback:
        verdict = _extract_verdict_text_from_json(data)
        feedback = verdict if verdict else _one_line(raw)[:500]

    scores = _extract_scores_from_json(data)
    confidence = _extract_confidence_from_json(data)

    return ParsedReviewResult(
        passed=bool(passed),
        feedback=feedback,
        scores=scores,
        confidence=confidence,
        raw_content=raw,
    )


def _parse_by_keywords(content: str) -> ParsedReviewResult:
    """通过 verdict/关键词判断评审结果。feedback 保留完整原文。"""
    verdict = _extract_explicit_verdict(content)
    if verdict:
        passed = _classify_verdict_text(verdict)
        if passed is not None:
            return ParsedReviewResult(
                passed=passed,
                feedback=content,  # 完整保留
                raw_content=content,
            )

    lower = content.lower()

    for pattern in _FAIL_VERDICT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return ParsedReviewResult(
                passed=False,
                feedback=content,
                raw_content=content,
            )

    for pattern in _PASS_VERDICT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return ParsedReviewResult(
                passed=True,
                feedback=content,
                raw_content=content,
            )

    # 默认通过（保守策略：避免误杀）
    return ParsedReviewResult(
        passed=True,
        feedback=content,
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
    # 1) 直接布尔字段
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

    # 2) verdict/decision 类字段
    verdict_text = _extract_verdict_text_from_json(data)
    if verdict_text:
        return _classify_verdict_text(verdict_text)

    # 3) feedback/summary 文本中的强信号
    feedback = _extract_feedback_from_json(data)
    if feedback:
        return _classify_verdict_text(feedback)

    return None


def _extract_feedback_from_json(data: dict[str, Any]) -> str:
    """提取完整 feedback 文本（不截断，截断由展示层负责）"""
    keys = (
        "feedback", "reason", "message", "summary", "conclusion",
        "details", "description", "recommendation",
    )
    for node in _walk_values(data):
        if isinstance(node, dict):
            for key in keys:
                value = node.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _extract_verdict_text_from_json(data: dict[str, Any]) -> str:
    keys = (
        "verdict", "decision", "final_decision", "final_verdict",
        "overall_verdict", "review_conclusion", "action", "status",
        "recommendation",
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
        # 例如 "4/5"
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


def _format_verdict_summary(verdict: str) -> str:
    if not verdict:
        return ""
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
