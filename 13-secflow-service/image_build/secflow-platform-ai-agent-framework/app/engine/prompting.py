from __future__ import annotations

import json
import re
from typing import Any, Dict


def _normalize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def render_prompt(template: str, variables: Dict[str, Any]) -> str:
    rendered = str(template)
    for key, value in variables.items():
        normalized = _normalize_value(value)
        rendered = re.sub(r"\{\{\s*" + re.escape(key) + r"\s*\}\}", normalized, rendered)
        rendered = re.sub(r"\$\{\s*" + re.escape(key) + r"\s*\}", normalized, rendered)
    return rendered


def build_text_phase_prompt(
    *,
    phase: str,
    user_prompt: str,
    context: Dict[str, Any],
    system_prompt: str = "",
) -> str:
    parts = [
        f"SECFLOW_PHASE: {phase}",
        "SECFLOW_CONTEXT_JSON_BEGIN",
        json.dumps(context, ensure_ascii=False, indent=2),
        "SECFLOW_CONTEXT_JSON_END",
    ]
    if system_prompt.strip():
        parts.extend(["", "# System Prompt", system_prompt.strip()])
    parts.extend(["", "# User Prompt", user_prompt.strip()])
    return "\n".join(parts).strip() + "\n"


def build_json_phase_prompt(
    *,
    phase: str,
    user_prompt: str,
    context: Dict[str, Any],
    schema_hint: Dict[str, Any],
    system_prompt: str = "",
) -> str:
    return build_text_phase_prompt(
        phase=phase,
        context=context,
        system_prompt=system_prompt,
        user_prompt=(
            f"{user_prompt.strip()}\n\n"
            "You must respond with a single JSON object only.\n"
            "Expected JSON schema example:\n"
            f"{json.dumps(schema_hint, ensure_ascii=False, indent=2)}"
        ),
    )


def extract_json_payload(content: str) -> Dict[str, Any]:
    text = str(content or "").strip()
    if not text:
        raise ValueError("empty response")

    fenced_match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S)
    if fenced_match:
        return json.loads(fenced_match.group(1))

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        return json.loads(text[first : last + 1])

    raise ValueError("response does not contain a JSON object")
