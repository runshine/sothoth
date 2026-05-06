from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional

from app.pi_vuln_core.review.models import ParsedReviewResult


@dataclass
class ResultReviewParseOutcome:
    parsed: ParsedReviewResult
    schema_valid: bool
    parser_mode: str
    repair_reason: str = ""
    needs_repair: bool = False


_ALLOWED_CANONICAL_VERDICTS = {"CONFIRMED", "FALSE_POSITIVE", "INSUFFICIENT_INFO"}

_CONFIDENCE_MAP = {
    "very_high": 0.95,
    "high": 0.85,
    "medium": 0.60,
    "moderate": 0.60,
    "low": 0.30,
    "very_low": 0.10,
}

_FALSE_POSITIVE_PATTERNS = [
    r"^false$",
    r"false[_ -]?positive",
    r"close[_ -]?as[_ -]?false[_ -]?positive",
    r"not a vulnerability",
    r"漏洞不存在",
    r"(?<!非)(?<!不是)误报",
    r"(?<!非)(?<!不是)假阳性",
    r"该漏洞报告为假阳性",
    r"核心攻击场景存在严重事实错误",
    r"报告声称.*实际上.*正确实现",
]

_INSUFFICIENT_INFO_PATTERNS = [
    r"insufficient[_ -]?info",
    r"unverified",
    r"cannot determine",
    r"unable to determine",
    r"证据不足",
    r"无法确认",
    r"无法判断",
]

_CONFIRMED_PATTERNS = [
    r"\btrue[_ -]?positive\b",
    r"\bconfirmed\b",
    r"\bverified\b",
    r"\bvalid\b",
    r"\bpass(?:ed)?\b",
]

_PARTIAL_BUT_REAL_PATTERNS = [
    r"partial(?:ly)?[_ -]?(?:valid|pass(?:ed)?|verified|confirmed|true[_ -]?positive)",
    r"confirmed[_ -]?with[_ -]?modifications?",
    r"confirm(?:ed)?[_ -]?with[_ -]?reduced[_ -]?severity",
]

_AMBIGUOUS_NEGATIVE_PATTERNS = [
    r"reject(?:ed)?",
    r"refut(?:e|ed)",
    r"dismiss(?:ed)?",
    r"invalid",
    r"\bfail(?:ed)?\b",
    r"驳回",
    r"未通过",
    r"不通过",
]

_VERDICT_KEYS = (
    "verdict",
    "verification_result",
    "verification_status",
    "decision",
    "final_decision",
    "overall_verdict",
    "final_verdict",
    "review_result",
    "validation_result",
    "status",
)

_FEEDBACK_KEYS = (
    "feedback",
    "summary",
    "conclusion",
    "reason",
    "message",
    "rationale",
    "justification",
    "recommendation",
    "description",
    "details",
    "analysis",
)


def parse_result_review_response(content: str) -> ResultReviewParseOutcome:
    raw = (content or "").strip()
    if not raw:
        parsed = ParsedReviewResult(
            passed=False,
            verdict="INSUFFICIENT_INFO",
            feedback="INSUFFICIENT_INFO（证据不足） - 结果评审返回空响应",
            feedback_detail="结果评审返回空响应",
            confidence=0.0,
            raw_content=content or "",
        )
        return ResultReviewParseOutcome(
            parsed=parsed,
            schema_valid=False,
            parser_mode="empty",
            repair_reason="结果评审返回空响应",
            needs_repair=True,
        )

    for candidate in _extract_json_candidates(raw):
        for variant, mode in ((candidate, "json"), (_repair_json_like_candidate(candidate), "json_repaired")):
            try:
                data = json.loads(variant)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            return _parse_result_review_dict(data, raw, parser_mode=mode)

    text_signal = _truth_signal_from_text(raw)
    if text_signal is not None:
        parsed = ParsedReviewResult(
            passed=text_signal[0],
            verdict=text_signal[1],
            feedback=_format_feedback(text_signal[1], raw),
            feedback_detail=raw,
            confidence=_extract_confidence_from_text(raw),
            raw_content=raw,
        )
        return ResultReviewParseOutcome(
            parsed=parsed,
            schema_valid=False,
            parser_mode="text_salvage",
            repair_reason="结果评审未返回可验证的 JSON 对象，仅能从文本中提取结论",
            needs_repair=True,
        )

    parsed = ParsedReviewResult(
        passed=False,
        verdict="INSUFFICIENT_INFO",
        feedback="INSUFFICIENT_INFO（证据不足） - 结果评审未返回可判定的标准 JSON",
        feedback_detail="结果评审未返回可判定的标准 JSON",
        confidence=0.0,
        raw_content=raw,
    )
    return ResultReviewParseOutcome(
        parsed=parsed,
        schema_valid=False,
        parser_mode="unparsed",
        repair_reason="结果评审未返回可判定的标准 JSON",
        needs_repair=True,
    )


def _parse_result_review_dict(
    data: dict[str, Any],
    raw: str,
    *,
    parser_mode: str,
) -> ResultReviewParseOutcome:
    schema_valid, schema_reason = _is_canonical_result_review_dict(data)

    signal = _truth_signal_from_bool_hints(data)
    if signal is None:
        signal = _truth_signal_from_verdict_fields(data)
    if signal is None:
        signal = _truth_signal_from_explicit_passed(data)
    if signal is None:
        signal = (False, "INSUFFICIENT_INFO")
        if not schema_reason:
            schema_reason = "缺少可判定 truth verdict"

    feedback_detail = _extract_feedback(data)
    if not feedback_detail:
        feedback_detail = _summarize_signal(signal[1])

    confidence = _extract_confidence(data)
    scores = _extract_scores(data)
    needs_repair = not schema_valid

    parsed = ParsedReviewResult(
        passed=signal[0],
        verdict=signal[1],
        feedback=_format_feedback(signal[1], feedback_detail),
        feedback_detail=feedback_detail,
        scores=scores,
        confidence=confidence,
        raw_content=raw,
    )
    return ResultReviewParseOutcome(
        parsed=parsed,
        schema_valid=schema_valid,
        parser_mode=("canonical_json" if schema_valid else parser_mode),
        repair_reason=(schema_reason if not schema_valid else ""),
        needs_repair=needs_repair,
    )


def _extract_json_candidates(raw: str) -> list[str]:
    candidates: list[str] = []
    candidates.append(raw)

    fenced = re.search(r"```json\s*\n?(.*?)\n?```", raw, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1).strip())

    first_brace = raw.find("{")
    last_brace = raw.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidates.append(raw[first_brace:last_brace + 1])

    unique: list[str] = []
    seen = set()
    for item in candidates:
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _repair_json_like_candidate(candidate: str) -> str:
    repaired = candidate
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


def _is_canonical_result_review_dict(data: dict[str, Any]) -> tuple[bool, str]:
    missing = [
        key for key in ("passed", "verdict", "feedback", "scores", "confidence")
        if key not in data
    ]
    if missing:
        return False, f"顶层缺少标准键: {', '.join(missing)}"

    passed = data.get("passed")
    if not isinstance(passed, bool):
        return False, "顶层 passed 必须是布尔值"

    verdict = str(data.get("verdict") or "").strip().upper()
    if verdict not in _ALLOWED_CANONICAL_VERDICTS:
        return False, f"顶层 verdict 非法: {verdict or '<empty>'}"

    if not isinstance(data.get("feedback"), str) or not str(data.get("feedback")).strip():
        return False, "顶层 feedback 不能为空字符串"

    scores = data.get("scores")
    if not isinstance(scores, dict):
        return False, "顶层 scores 必须是对象"
    if "issue_truth" not in scores:
        return False, "scores 缺少必需字段 issue_truth"
    if not _is_strict_numeric(scores.get("issue_truth")):
        return False, "scores.issue_truth 必须是数值型 0.0-1.0"
    issue_truth = float(scores["issue_truth"])
    if issue_truth < 0.0 or issue_truth > 1.0:
        return False, "scores.issue_truth 超出 0.0-1.0 范围"

    confidence = data.get("confidence")
    if not _is_strict_numeric(confidence):
        return False, "顶层 confidence 必须是数值型 0.0-1.0"
    confidence_value = float(confidence)
    if confidence_value < 0.0 or confidence_value > 1.0:
        return False, "顶层 confidence 超出 0.0-1.0 范围"

    if passed and verdict != "CONFIRMED":
        return False, "passed=true 时 verdict 必须为 CONFIRMED"
    if not passed and verdict == "CONFIRMED":
        return False, "passed=false 时 verdict 不能为 CONFIRMED"
    return True, ""


def _should_repair_noncanonical_dict(
    data: dict[str, Any],
    signal: tuple[bool, str],
) -> bool:
    explicit_passed = _coerce_bool(data.get("passed"))
    if explicit_passed is True:
        return False
    if explicit_passed is False:
        if _has_explicit_verdict_signal(data, (False, "FALSE_POSITIVE")):
            return False
        if _has_explicit_verdict_signal(data, (False, "INSUFFICIENT_INFO")):
            return False
        return True

    if _find_bool(data, ("is_false_positive", "false_positive")) is True:
        return False
    if _find_bool(data, ("is_vulnerability_real", "vulnerability_confirmed", "vulnerability_exists")) is True:
        return False
    if _find_bool(data, ("is_vulnerability_real", "vulnerability_confirmed", "vulnerability_exists")) is False:
        return False

    return True


def _has_explicit_verdict_signal(
    data: dict[str, Any],
    expected: tuple[bool, str],
) -> bool:
    for key in _VERDICT_KEYS:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        if _truth_signal_from_text(value) == expected:
            return True

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _VERDICT_KEYS:
            value = node.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if _truth_signal_from_text(value) == expected:
                return True
    return False


def _truth_signal_from_bool_hints(data: dict[str, Any]) -> tuple[bool, str] | None:
    false_positive = _find_bool(data, ("is_false_positive", "false_positive"))
    if false_positive is True:
        return False, "FALSE_POSITIVE"

    vulnerability_real = _find_bool(
        data,
        ("is_vulnerability_real", "vulnerability_confirmed", "vulnerability_exists"),
    )
    if vulnerability_real is True:
        return True, "CONFIRMED"
    if vulnerability_real is False:
        return False, "FALSE_POSITIVE"
    return None


def _truth_signal_from_verdict_fields(data: dict[str, Any]) -> tuple[bool, str] | None:
    for key in _VERDICT_KEYS:
        signal = _truth_signal_from_text_value(data.get(key))
        if signal is not None:
            return signal

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _VERDICT_KEYS:
            signal = _truth_signal_from_text_value(node.get(key))
            if signal is not None:
                return signal
    return None


def _truth_signal_from_explicit_passed(data: dict[str, Any]) -> tuple[bool, str] | None:
    for key in ("passed", "pass", "approved", "accepted"):
        if key not in data:
            continue
        bool_value = _coerce_bool(data.get(key))
        if bool_value is None:
            continue
        verdict = "CONFIRMED" if bool_value else "INSUFFICIENT_INFO"
        top_level_verdict = _truth_signal_from_text_value(data.get("verdict"))
        if top_level_verdict is not None:
            return top_level_verdict
        return bool_value, verdict
    return None


def _truth_signal_from_text_value(value: Any) -> tuple[bool, str] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return _truth_signal_from_text(value)


def _truth_signal_from_text(text: str) -> tuple[bool, str] | None:
    low = text.strip().lower()
    if not low:
        return None

    if _matches_any(low, _FALSE_POSITIVE_PATTERNS):
        return False, "FALSE_POSITIVE"
    if _matches_any(low, _INSUFFICIENT_INFO_PATTERNS):
        return False, "INSUFFICIENT_INFO"
    if _matches_any(low, _PARTIAL_BUT_REAL_PATTERNS):
        return True, "CONFIRMED"
    if _matches_any(low, _CONFIRMED_PATTERNS):
        return True, "CONFIRMED"
    if _matches_any(low, _AMBIGUOUS_NEGATIVE_PATTERNS):
        return None
    return None


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _canonicalize_verdict(verdict: str) -> str:
    signal = _truth_signal_from_text(verdict)
    if signal is None:
        return verdict.strip().upper()
    return signal[1]


def _extract_feedback(data: dict[str, Any]) -> str:
    for key in _FEEDBACK_KEYS:
        value = data.get(key)
        rendered = _stringify(value)
        if rendered:
            return rendered

    for node in _walk_values(data):
        if not isinstance(node, dict) or node is data:
            continue
        for key in _FEEDBACK_KEYS:
            rendered = _stringify(node.get(key))
            if rendered:
                return rendered
    return ""


def _stringify(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        if items:
            return "\n".join(items)
    return ""


def _extract_confidence(data: dict[str, Any], *, top_level_only: bool = False) -> float:
    value = _extract_confidence_value(data, top_level_only=top_level_only)
    if value is None:
        return 0.0
    return value


def _extract_confidence_value(data: dict[str, Any], *, top_level_only: bool = False) -> float | None:
    nodes = [data] if top_level_only else list(_walk_values(data))
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key in ("confidence", "confidence_level"):
            if key not in node:
                continue
            value = _normalize_float(node.get(key))
            if value is not None:
                return value
    return None


def _extract_confidence_from_text(text: str) -> float:
    match = re.search(r'"confidence"\s*:\s*"?(very_high|high|medium|moderate|low|very_low|\d+(?:\.\d+)?)"?', text, re.IGNORECASE)
    if not match:
        return 0.0
    return _normalize_float(match.group(1)) or 0.0


def _extract_scores(data: dict[str, Any]) -> dict[str, float]:
    if isinstance(data.get("scores"), dict):
        return {str(k): _normalize_float(v) or 0.0 for k, v in data["scores"].items()}
    return {}


def _normalize_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in _CONFIDENCE_MAP:
        return _CONFIDENCE_MAP[text]
    try:
        return float(text)
    except ValueError:
        return None


def _is_strict_numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _coerce_bool(value: Any) -> Optional[bool]:
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


def _find_bool(data: dict[str, Any], keys: tuple[str, ...]) -> Optional[bool]:
    for node in _walk_values(data):
        if not isinstance(node, dict):
            continue
        for key in keys:
            if key not in node:
                continue
            bool_value = _coerce_bool(node.get(key))
            if bool_value is not None:
                return bool_value
    return None


def _walk_values(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _walk_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_values(item)


def _summarize_signal(verdict: str) -> str:
    if verdict == "CONFIRMED":
        return "底层问题真实存在"
    if verdict == "FALSE_POSITIVE":
        return "该报告属于误报"
    return "无法确认底层问题是否真实存在"


def _format_feedback(verdict: str, detail: str) -> str:
    summary = {
        "CONFIRMED": "CONFIRMED（已确认）",
        "FALSE_POSITIVE": "FALSE_POSITIVE（误报）",
        "INSUFFICIENT_INFO": "INSUFFICIENT_INFO（证据不足）",
    }.get(verdict, verdict)
    detail = re.sub(r"\s+", " ", (detail or "")).strip()
    if not detail:
        return summary
    return f"{summary} - {detail}"[:300]
