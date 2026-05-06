from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from app.pi_vuln_core.review.models import ParsedReviewResult, parse_review_response


@dataclass
class GlobalReviewParseOutcome:
    parsed: ParsedReviewResult
    schema_valid: bool
    parser_mode: str
    repair_reason: str = ""
    needs_repair: bool = False


_REQUIRED_GLOBAL_SCORE_KEYS = (
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "vuln_pattern_breadth",
    "code_evidence_depth",
    "limitations_honesty",
    "report_completeness",
)


def parse_global_review_response(
    content: str,
    required_score_keys: Iterable[str] | None = None,
) -> GlobalReviewParseOutcome:
    raw = (content or "").strip()
    if not raw:
        parsed = ParsedReviewResult(
            passed=False,
            verdict="FAIL",
            feedback="FAIL（未通过） - 全局评审返回空响应",
            feedback_detail="全局评审返回空响应",
            confidence=0.0,
            raw_content=content or "",
        )
        return GlobalReviewParseOutcome(
            parsed=parsed,
            schema_valid=False,
            parser_mode="empty",
            repair_reason="全局评审返回空响应",
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
            return _parse_global_review_dict(
                data,
                raw,
                parser_mode=mode,
                required_score_keys=required_score_keys,
            )

    parsed = parse_review_response(content)
    return GlobalReviewParseOutcome(
        parsed=parsed,
        schema_valid=False,
        parser_mode="fallback",
        repair_reason="全局评审未返回可验证的 JSON 对象",
        needs_repair=True,
    )


def _parse_global_review_dict(
    data: dict[str, Any],
    raw: str,
    *,
    parser_mode: str,
    required_score_keys: Iterable[str] | None = None,
) -> GlobalReviewParseOutcome:
    schema_valid, schema_reason = _is_canonical_global_review_dict(
        data,
        required_score_keys=required_score_keys,
    )
    parsed = parse_review_response(raw)
    return GlobalReviewParseOutcome(
        parsed=parsed,
        schema_valid=schema_valid,
        parser_mode=("canonical_json" if schema_valid else parser_mode),
        repair_reason=(schema_reason if not schema_valid else ""),
        needs_repair=not schema_valid,
    )


def _is_canonical_global_review_dict(
    data: dict[str, Any],
    required_score_keys: Iterable[str] | None = None,
) -> tuple[bool, str]:
    missing = [key for key in ("passed", "feedback", "scores", "confidence") if key not in data]
    if missing:
        return False, f"顶层缺少标准键: {', '.join(missing)}"

    passed = data.get("passed")
    if not isinstance(passed, bool):
        return False, "顶层 passed 必须是布尔值"

    feedback = data.get("feedback")
    if not isinstance(feedback, str) or not feedback.strip():
        return False, "顶层 feedback 不能为空字符串"

    scores = data.get("scores")
    if not isinstance(scores, dict):
        return False, "顶层 scores 必须是对象"

    required_keys = tuple(required_score_keys or _REQUIRED_GLOBAL_SCORE_KEYS)
    missing_scores = [key for key in required_keys if key not in scores]
    if missing_scores:
        return False, f"scores 缺少必需分数字段: {', '.join(missing_scores)}"

    for key in required_keys:
        if not _is_strict_numeric(scores.get(key)):
            return False, f"scores.{key} 必须是数值型 0.0-1.0"
        value = float(scores[key])
        if value < 0.0 or value > 1.0:
            return False, f"scores.{key} 超出 0.0-1.0 范围"

    confidence = data.get("confidence")
    if not _is_strict_numeric(confidence):
        return False, "顶层 confidence 必须是数值型 0.0-1.0"
    confidence_value = float(confidence)
    if confidence_value < 0.0 or confidence_value > 1.0:
        return False, "顶层 confidence 超出 0.0-1.0 范围"

    if "verdict" in data:
        verdict = str(data.get("verdict") or "").strip().upper()
        if verdict not in {"PASS", "FAIL"}:
            return False, f"顶层 verdict 非法: {verdict or '<empty>'}"
        if passed and verdict != "PASS":
            return False, "passed=true 时 verdict 必须为 PASS"
        if not passed and verdict != "FAIL":
            return False, "passed=false 时 verdict 必须为 FAIL"

    if "issues" in data and not isinstance(data.get("issues"), list):
        return False, "顶层 issues 必须是数组"
    # passed=true 时允许 issues 为空或不存在（不再强制报错）

    if "resolved_issues" in data and not isinstance(data.get("resolved_issues"), list):
        return False, "顶层 resolved_issues 必须是数组"

    return True, ""


def _is_strict_numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _extract_json_candidates(raw: str) -> list[str]:
    candidates: list[str] = [raw]

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
    repaired = candidate or ""
    repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
    return repaired
