"""Threat model template catalog and rendering helpers."""

from __future__ import annotations

import re
from typing import Any


BUILTIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "builtin-default-validation",
        "scope": "builtin",
        "name": "通用漏洞可利用性验证",
        "description": "围绕漏洞成因、前置条件、利用路径和影响面进行自动化验证。",
        "content": """# Threat Model: {{case_title}}

## Target
- Case ID: `{{case_id}}`
- Subject: `{{subject_locator}}`
- Severity: `{{severity}}`
- Category: `{{category}}`

## Security Goal
Validate whether the reported weakness is practically exploitable in the provided source and binary context. Prefer evidence from code paths, binary symbols, configuration, reachable entry points, and concrete data/control-flow constraints.

## Key Questions
1. Is the vulnerable code reachable from an attacker-controlled entry point?
2. Are the reported source locations and binary artifacts consistent?
3. What preconditions are required to trigger the issue?
4. What impact can be demonstrated or reasonably inferred?
5. What evidence rules out false positives?

## Case Summary
{{summary}}

## Evidence Hints
{{evidence_summary}}

## Output Expectations
- Give a verdict for each report item: confirmed / rejected / inconclusive.
- Include concise reasoning, evidence references, and ruled-out conditions.
- Do not generate HTML reports; structured report-data is consumed by the SecFlow React UI.
""".strip(),
    },
    {
        "id": "builtin-memory-safety",
        "scope": "builtin",
        "name": "内存安全专项验证",
        "description": "面向越界、UAF、空指针、整数溢出等内存安全问题。",
        "content": """# Memory Safety Threat Model: {{case_title}}

Focus on memory safety exploitability for `{{subject_locator}}`.

## Analyze
- Tainted inputs and parser/IPC/network/file entry points.
- Bounds, lifetime, ownership, integer conversion and allocation size checks.
- Binary-level mitigations and whether they block practical exploitation.

## Case Context
- Severity: {{severity}}
- Summary: {{summary}}
- Evidence: {{evidence_summary}}

Return only structured verification findings suitable for report-data rendering.
""".strip(),
    },
    {
        "id": "builtin-authz-logic",
        "scope": "builtin",
        "name": "权限与业务逻辑验证",
        "description": "面向认证绕过、越权、策略缺陷和敏感操作保护不足。",
        "content": """# Authorization / Logic Threat Model: {{case_title}}

Assess whether the reported issue allows unauthorized access or policy bypass.

## Verify
- Required identity, role, tenant/project boundary and trust zone.
- Missing checks before sensitive operations.
- Confused deputy, insecure defaults, and fallback/error paths.
- Concrete impact and compensating controls.

## Case Context
Subject: {{subject_locator}}
Summary: {{summary}}
Evidence: {{evidence_summary}}
""".strip(),
    },
]

_PATTERN = re.compile(r"{{\s*([a-zA-Z0-9_.-]+)\s*}}")


def build_case_variables(case_payload: dict[str, Any]) -> dict[str, str]:
    subject = case_payload.get("subject") if isinstance(case_payload.get("subject"), dict) else {}
    evidence = case_payload.get("evidence") if isinstance(case_payload.get("evidence"), dict) else {}
    return {
        "case_id": str(case_payload.get("id") or ""),
        "case_title": str(case_payload.get("title") or "Untitled case"),
        "summary": str(case_payload.get("summary") or "No summary provided."),
        "severity": str(case_payload.get("severity") or "unknown"),
        "category": str(case_payload.get("category") or case_payload.get("rule_name") or "unknown"),
        "subject_locator": str(subject.get("locator") or subject.get("name") or "unknown"),
        "subject_type": str(subject.get("type") or "unknown"),
        "evidence_summary": str(evidence.get("summary") or evidence.get("reproduction_hint") or "No evidence summary provided."),
    }


def list_templates(project_id: str | None = None) -> list[dict[str, Any]]:
    # MVP: builtin templates. project_id is accepted for forward-compatible project-level templates.
    return [{k: v for k, v in item.items() if k != "content"} for item in BUILTIN_TEMPLATES]


def get_template(template_id: str) -> dict[str, Any] | None:
    return next((item for item in BUILTIN_TEMPLATES if item["id"] == template_id), None)


def render_template(template_id: str, case_payload: dict[str, Any], overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    template = get_template(template_id)
    if template is None:
        raise KeyError(template_id)
    variables = build_case_variables(case_payload)
    for key, value in (overrides or {}).items():
        variables[str(key)] = str(value)

    def replace(match: re.Match[str]) -> str:
        return variables.get(match.group(1), "")

    return {
        "template_id": template["id"],
        "name": template["name"],
        "content": _PATTERN.sub(replace, template["content"]),
        "variables": variables,
    }
