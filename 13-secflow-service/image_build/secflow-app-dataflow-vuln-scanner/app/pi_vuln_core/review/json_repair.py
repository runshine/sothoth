from __future__ import annotations

import re

_JSON_KEY_NAME_RE = r"[A-Za-z_][A-Za-z0-9_-]*"


def repair_json_like_candidate(candidate: str) -> str:
    """Best-effort repair for common LLM JSON typos.

    This helper is intentionally conservative and only fixes patterns we see
    frequently in review outputs:
    - trailing commas before `}` / `]`
    - numeric range values accidentally emitted as `1 - 2`
    - object keys missing one or both surrounding quotes, e.g.
      `{foo: 1}`, `{foo": 1}`, `{"foo: 1}`

    It is not a general JSON sanitizer; callers must still run `json.loads`
    afterwards and fail closed if parsing remains invalid.
    """

    repaired = candidate or ""

    def _fix_range_value(m: re.Match) -> str:
        cleaned = re.sub(r"\s+", "", m.group(2))
        return f'{m.group(1)}"{cleaned}"{m.group(3)}'

    repaired = re.sub(
        r'(:\s*)(\d+\s*-\s*\d+)(\s*[,}\]])',
        _fix_range_value,
        repaired,
    )

    # Missing leading quote: {foo": 1} / ,foo": 1
    repaired = re.sub(
        rf'([,{{]\s*)({_JSON_KEY_NAME_RE})"(\s*:)',
        r'\1"\2"\3',
        repaired,
    )
    # Missing trailing quote: {"foo: 1} / ,"foo: 1
    repaired = re.sub(
        rf'([,{{]\s*)"({_JSON_KEY_NAME_RE})(\s*:)',
        r'\1"\2"\3',
        repaired,
    )
    # Missing both quotes: {foo: 1} / ,foo: 1
    repaired = re.sub(
        rf'([,{{]\s*)({_JSON_KEY_NAME_RE})(\s*:)',
        r'\1"\2"\3',
        repaired,
    )

    repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
    return repaired
