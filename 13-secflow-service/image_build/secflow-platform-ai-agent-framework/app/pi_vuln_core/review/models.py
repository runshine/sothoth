"""
评审结果解析工具

解析智能体评审响应，提取通过/不通过及反馈内容
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedReviewResult:
    """解析后的评审结果"""
    passed: bool
    feedback: str = ""
    scores: dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    raw_content: str = ""


def parse_review_response(content: str) -> ParsedReviewResult:
    """
    解析评审智能体的响应内容

    支持多种格式：
    1. JSON 格式: {"passed": true/false, "feedback": "...", "scores": {...}}
    2. 关键词检测: PASS/FAIL/通过/不通过
    3. 默认：视为通过（保守策略）
    """
    raw = content.strip()

    # 尝试 JSON 解析
    json_result = _try_parse_json(raw)
    if json_result is not None:
        return json_result

    # 关键词检测
    return _parse_by_keywords(raw)


def _try_parse_json(content: str) -> Optional[ParsedReviewResult]:
    """尝试从响应中提取 JSON"""
    # 尝试直接解析
    try:
        data = json.loads(content)
        return _json_to_result(data, content)
    except (json.JSONDecodeError, TypeError):
        pass

    # 尝试提取 ```json ... ``` 代码块
    json_match = re.search(r'```json\s*\n?(.*?)\n?```', content, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(1))
            return _json_to_result(data, content)
        except (json.JSONDecodeError, TypeError):
            pass

    # 尝试提取 { ... } 块
    brace_match = re.search(r'\{[^{}]*"passed"\s*:.*?\}', content, re.DOTALL)
    if brace_match:
        try:
            data = json.loads(brace_match.group(0))
            return _json_to_result(data, content)
        except (json.JSONDecodeError, TypeError):
            pass

    return None


def _json_to_result(data: dict, raw: str) -> ParsedReviewResult:
    """将 JSON dict 转为 ParsedReviewResult"""
    passed = data.get("passed", data.get("pass", True))
    if isinstance(passed, str):
        passed = passed.lower() in ("true", "yes", "pass", "通过")

    return ParsedReviewResult(
        passed=bool(passed),
        feedback=str(data.get("feedback", data.get("reason", ""))),
        scores=data.get("scores", {}),
        confidence=float(data.get("confidence", 0.0)),
        raw_content=raw,
    )


def _parse_by_keywords(content: str) -> ParsedReviewResult:
    """通过关键词判断评审结果"""
    lower = content.lower()

    # 强烈不通过信号
    fail_signals = [
        "不通过", "未通过", "reject", "fail", "不合格",
        "误报", "false positive", "需要修改", "需要重做",
    ]
    for signal in fail_signals:
        if signal in lower:
            return ParsedReviewResult(
                passed=False,
                feedback=content[:500],
                raw_content=content,
            )

    # 强烈通过信号
    pass_signals = [
        "通过", "合格", "approve", "pass", "accept",
        "no issues", "looks good", "lgtm",
    ]
    for signal in pass_signals:
        if signal in lower:
            return ParsedReviewResult(
                passed=True,
                feedback=content[:500],
                raw_content=content,
            )

    # 默认通过（保守策略：避免误杀）
    return ParsedReviewResult(
        passed=True,
        feedback=f"[无法明确判断，默认通过] {content[:300]}",
        raw_content=content,
    )
