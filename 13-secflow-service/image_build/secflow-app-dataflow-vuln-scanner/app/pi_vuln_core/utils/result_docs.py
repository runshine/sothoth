from __future__ import annotations

import hashlib
import re
from pathlib import Path

from app.pi_vuln_core.utils.file_ops import write_json

_RESULT_REPORT_RE = re.compile(r"^result_(\d+)\.md$")
_RESULT_REF_RE = re.compile(r"\bresult_\d+\.md\b")
_INPUT_REF_RE = re.compile(r"\b(?:INPUT|IN)[-_\s]?\d+\b", re.IGNORECASE)
_BACKTICK_TOKEN_RE = re.compile(r"`([^`\n]{2,120})`")
_IDENT_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_FUNCTION_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
_LINE_REF_RE = re.compile(r"\bL(\d{2,8})\b|\[L(\d{2,8})\]")
_DATAFLOW_INPUT_HEADING_RE = re.compile(
    r"^\s*#{2,8}\s*(?:INPUT|IN)[-_\s]?(\d+)\s*[:：]\s*(.+?)\s*(?:🔴|$)",
    re.IGNORECASE,
)
_TASK_DATAFLOW_PATH_RE = re.compile(r"`([^`\n]+\.md)`")
_TASK_COUNT_PATTERNS = {
    "input": re.compile(r"(\d+)\s*个外部输入"),
    "export": re.compile(r"(\d+)\s*个\s*EXPORT", re.IGNORECASE),
    "used": re.compile(r"(\d+)\s*个\s*USED", re.IGNORECASE),
    "cleaned": re.compile(r"CLEANED\s*=\s*(\d+)", re.IGNORECASE),
}
_DANGEROUS_ENDPOINT_RE = re.compile(
    r"(?i)(MBUF_|RAW_U(?:8|16|32|64)|memcpy|memset|copy|malloc|free|cut|"
    r"checksum|VOS_MemCmp|SSP_Debug|Debug|AUTH_|VRP_|SOCK_Recv|CreateControlInfo)"
)
_VULN_HEADING_RE = re.compile(
    r"(?im)^\s{0,3}#{1,6}\s*(?:漏洞(?:报告|分析|补充分析)?\s*[:：-]\s*)?(VULN-\d+)\b",
)
_SUPPLEMENT_KEYWORD_RE = re.compile(
    r"(?i)(补充分析|补充报告|补充说明|补丁分析|修正|更正|勘误|supplement|correction|corrigendum|amendment|follow-up)",
)
_SUPPLEMENT_NATURE_RE = re.compile(
    r"(?i)(本报告性质|报告性质|document type|report type)[^\n]{0,80}"
    r"(补充分析|补充报告|修正|更正|supplement|correction|amendment)",
)
_WITHDRAWN_RE = re.compile(
    r"(?im)"
    r"(?:^\s*#.*(?:已?撤回|withdrawn|retraction|撤销)|"
    r"^\s*-\s*\*\*(?:状态|status|本报告性质|报告性质|document type|report type)\*\*\s*[:：]"
    r".*(?:已?撤回|withdrawn|retraction|撤销)|"
    r"(?:修正|更正|勘误|correction|corrigendum)[^\n]{0,80}(?:撤回|withdrawn|retraction))"
)
_FALSE_POSITIVE_RE = re.compile(
    r"(?im)"
    r"(?:^\s*#.*(?:误报|非漏洞|证伪|false positive|invalid finding|not a vulnerability)|"
    r"^\s*-\s*\*\*(?:状态|status|结论|verdict|本报告性质|报告性质)\*\*\s*[:：]"
    r".*(?:误报|非漏洞|证伪|false positive|invalid finding|not a vulnerability)|"
    r"(?:确认为|判定为|confirmed as|classified as)[^\n]{0,80}"
    r"(?:误报|非漏洞|false positive|invalid finding))"
)
_SUPERSEDED_RE = re.compile(
    r"(?im)"
    r"(?:^\s*#.*(?:已被替代|被.*替代|superseded)|"
    r"^\s*-\s*\*\*(?:状态|status|本报告性质|报告性质)\*\*\s*[:：].*(?:已被替代|superseded)|"
    r"(?:被|由)\s*`?result_\d+\.md`?[^\n]{0,40}(?:替代|取代)|"
    r"superseded\s+by\s+`?result_\d+\.md`?)"
)
_SUPPORTING_DOC_RE = re.compile(
    r"(?im)"
    r"(?:^\s*#.*(?:附录|覆盖矩阵|证据矩阵|支撑材料|辅助文档|supporting doc|appendix|coverage matrix)|"
    r"^\s*-\s*\*\*(?:本报告性质|报告性质|document type|report type)\*\*\s*[:：]"
    r".*(?:附录|支撑材料|辅助文档|supporting doc|appendix))"
)
_RELATION_PATTERNS = [
    re.compile(
        r"(?i)(?:原始报告|原报告|关联漏洞|关联报告|关联结果|关联文件|original report|related report|related result)"
        r"[^\n]{0,120}?(result_\d+\.md)"
    ),
]

_ENDPOINT_LABELS = {
    "export": "EXPORT",
    "used": "USED",
    "cleaned": "CLEANED",
}
_OBLIGATION_KEYS = {
    "input": "input_ids",
    "export": "export_symbols",
    "used": "used_symbols",
    "cleaned": "cleaned_symbols",
    "star": "star_findings",
}
_OBLIGATION_LABELS = {
    "input": "INPUT",
    "export": "EXPORT",
    "used": "USED",
    "cleaned": "CLEANED",
    "star": "STAR",
}
_ENDPOINT_SKIP_TOKENS = {
    "input",
    "in",
    "export",
    "used",
    "cleaned",
    "result",
    "summary",
    "vuln",
    "cwe",
    "true",
    "false",
    "status",
    "documented",
    "source_closed",
    "accepted_residual",
    "external_blocked",
}


def extract_result_number(name: str) -> int | None:
    match = _RESULT_REPORT_RE.match(name)
    if not match:
        return None
    return int(match.group(1))


def is_result_report_filename(name: str) -> bool:
    return extract_result_number(name) is not None


def list_result_report_files(dir_path: str | Path) -> list[str]:
    path = Path(dir_path)
    if not path.is_dir():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file() and is_result_report_filename(item.name)
    )


def extract_final_result_files_from_summary(
    summary_file: str | Path,
    available_results: list[str] | None = None,
) -> list[str]:
    path = Path(summary_file)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    available = set(available_results or [])
    in_summary_table = False
    seen_table = False
    selected: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("##"):
            heading = re.sub(r"^#+\s*", "", line)
            heading = re.sub(r"^\d+(?:\.\d+)*\s*[.、]?\s*", "", heading).strip()
            in_summary_table = "漏洞汇总" in heading or "漏洞列表" in heading
            seen_table = False
            continue

        if not in_summary_table:
            continue

        if line.startswith("|"):
            refs = _RESULT_REF_RE.findall(line)
            if refs:
                seen_table = True
            for ref in refs:
                if available and ref not in available:
                    continue
                if ref not in selected:
                    selected.append(ref)
            continue

        if seen_table and line:
            break

    return selected


def extract_all_result_references_from_summary(
    summary_file: str | Path,
    available_results: list[str] | None = None,
) -> list[str]:
    path = Path(summary_file)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    available = set(available_results or [])
    refs: list[str] = []
    for ref in _RESULT_REF_RE.findall(content):
        if available and ref not in available:
            continue
        if ref not in refs:
            refs.append(ref)
    return refs


def extract_endpoint_mentions_from_text(content: str) -> dict[str, list[str]]:
    """Best-effort deterministic endpoint extractor for review ledgers."""
    text = content or ""
    input_ids = [
        _canonical_input_ref(match.group(0))
        for match in _INPUT_REF_RE.finditer(text)
    ]
    code_symbols = _extract_code_symbols_from_text(text)
    by_label: dict[str, list[str]] = {key: [] for key in _ENDPOINT_LABELS}
    star_findings: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        upper = line.upper()
        if not line:
            continue
        if "★" in line or "关键发现" in line:
            star_findings.append(line[:180])
        for key, label in _ENDPOINT_LABELS.items():
            if label not in upper:
                continue
            for token in _extract_endpoint_tokens_from_line(line):
                if token.lower() not in _ENDPOINT_SKIP_TOKENS:
                    by_label[key].append(token)

    return {
        "input_ids": _dedupe_sorted(input_ids),
        "export_symbols": _dedupe_sorted(by_label["export"]),
        "used_symbols": _dedupe_sorted(by_label["used"]),
        "cleaned_symbols": _dedupe_sorted(by_label["cleaned"]),
        "star_findings": _dedupe_preserve_order(star_findings),
        "code_symbols": _dedupe_sorted(code_symbols),
    }


def _extract_code_symbols_from_text(text: str) -> list[str]:
    symbols: list[str] = []
    for token in _BACKTICK_TOKEN_RE.findall(text or ""):
        cleaned = token.strip()
        if not cleaned or cleaned.startswith("result_"):
            continue
        if re.search(r"[A-Za-z_][A-Za-z0-9_]{2,}", cleaned):
            symbols.append(cleaned)
    for match in _FUNCTION_CALL_RE.finditer(text or ""):
        symbols.append(match.group(1))
    for match in re.finditer(r"\b(?:RAW_U(?:8|16|32|64)|[A-Za-z_][A-Za-z0-9_]{2,}\[[^\]\n]{1,40}\])\b", text or ""):
        symbols.append(match.group(0))
    return symbols[:5000]


def _canonical_input_ref(value: str) -> str:
    match = re.search(r"\d+", value or "")
    if not match:
        return re.sub(r"[-_\s]+", "-", (value or "").upper())
    return f"INPUT-{int(match.group(0))}"


def _extract_endpoint_tokens_from_line(line: str) -> list[str]:
    tokens: list[str] = []
    for token in _BACKTICK_TOKEN_RE.findall(line):
        cleaned = token.strip()
        if cleaned and not cleaned.startswith("result_"):
            tokens.append(cleaned)
    if tokens:
        return tokens

    label_pos = min(
        (pos for label in _ENDPOINT_LABELS.values() if (pos := line.upper().find(label)) >= 0),
        default=-1,
    )
    tail = line[label_pos:] if label_pos >= 0 else line
    for token in _IDENT_TOKEN_RE.findall(tail):
        if token.upper() in set(_ENDPOINT_LABELS.values()):
            continue
        tokens.append(token)
    return tokens[:8]


def _dedupe_sorted(items: list[str]) -> list[str]:
    return sorted({item for item in items if item})


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _merge_endpoint_mentions(*mentions_list: dict[str, list[str]]) -> dict[str, list[str]]:
    keys = {
        "input_ids",
        "export_symbols",
        "used_symbols",
        "cleaned_symbols",
        "star_findings",
        "code_symbols",
    }
    merged: dict[str, list[str]] = {key: [] for key in keys}
    for mentions in mentions_list:
        if not isinstance(mentions, dict):
            continue
        for key in keys:
            merged[key].extend(mentions.get(key) or [])
    return {
        "input_ids": _dedupe_sorted(merged["input_ids"]),
        "export_symbols": _dedupe_sorted(merged["export_symbols"]),
        "used_symbols": _dedupe_sorted(merged["used_symbols"]),
        "cleaned_symbols": _dedupe_sorted(merged["cleaned_symbols"]),
        "star_findings": _dedupe_preserve_order(merged["star_findings"]),
        "code_symbols": _dedupe_sorted(merged["code_symbols"]),
    }


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _read_text_if_exists(path: str | Path | None) -> str:
    if not path:
        return ""
    candidate = Path(path)
    if not candidate.is_file():
        return ""
    return candidate.read_text(encoding="utf-8", errors="replace")


def infer_result_lifecycle_from_text(content: str, filename: str = "") -> dict[str, object]:
    """Infer the framework lifecycle bucket for a result_NNN.md file.

    The detector intentionally looks at the document head and explicit metadata.
    It is a guardrail for correction/withdrawal artifacts, not a deep semantic
    vulnerability classifier.
    """
    head = "\n".join(content.splitlines()[:40])
    head = head[:6000]
    signals: list[str] = []

    status = "candidate"
    active = True
    delivery_bucket = "results"

    if _WITHDRAWN_RE.search(head):
        status = "withdrawn"
        active = False
        delivery_bucket = "removed_results"
        signals.append("withdrawn_marker")
    elif _FALSE_POSITIVE_RE.search(head):
        status = "false_positive"
        active = False
        delivery_bucket = "removed_results"
        signals.append("false_positive_marker")
    elif _SUPERSEDED_RE.search(head):
        status = "superseded"
        active = False
        delivery_bucket = "removed_results"
        signals.append("superseded_marker")
    elif _SUPPORTING_DOC_RE.search(head):
        status = "supporting_doc"
        active = False
        delivery_bucket = "supporting_docs"
        signals.append("supporting_doc_marker")

    return {
        "filename": filename,
        "status": status,
        "active": active,
        "delivery_bucket": delivery_bucket,
        "signals": signals,
    }


def infer_result_lifecycle(result_path: str | Path) -> dict[str, object]:
    path = Path(result_path)
    return infer_result_lifecycle_from_text(_read_text(path), path.name)


def extract_vulnerability_headings_from_result(result_path: str | Path) -> list[str]:
    content = _read_text(result_path)
    vuln_ids: list[str] = []
    for match in _VULN_HEADING_RE.finditer(content):
        vuln_id = str(match.group(1)).upper()
        if vuln_id not in vuln_ids:
            vuln_ids.append(vuln_id)
    return vuln_ids


def collect_multi_finding_result_reports(results_dir: str | Path) -> dict[str, list[str]]:
    results_path = Path(results_dir)
    findings: dict[str, list[str]] = {}
    for filename in list_result_report_files(results_path):
        vuln_ids = extract_vulnerability_headings_from_result(results_path / filename)
        if len(vuln_ids) > 1:
            findings[filename] = vuln_ids
    return findings


def _infer_result_relationship(result_path: str | Path) -> dict[str, object]:
    path = Path(result_path)
    filename = path.name
    content = _read_text(path)
    head = content[:4000]
    lines = [line.strip() for line in head.splitlines() if line.strip()]
    title = next((line for line in lines if line.startswith("#")), "")
    lifecycle = infer_result_lifecycle_from_text(content, filename)

    supplement_signals: list[str] = []
    if title and _SUPPLEMENT_KEYWORD_RE.search(title):
        supplement_signals.append("title_keyword")
    if _SUPPLEMENT_NATURE_RE.search(head):
        supplement_signals.append("report_nature")

    related_candidates: list[str] = []
    for pattern in _RELATION_PATTERNS:
        for match in pattern.finditer(head):
            ref = match.group(1)
            if ref != filename and ref not in related_candidates:
                related_candidates.append(ref)

    top_refs = [ref for ref in _RESULT_REF_RE.findall(head) if ref != filename]
    if not related_candidates and len(dict.fromkeys(top_refs)) == 1 and supplement_signals:
        related_candidates = list(dict.fromkeys(top_refs))

    role = "supplement" if supplement_signals and related_candidates else "finding"
    related_to = related_candidates[0] if role == "supplement" else ""
    vulnerability_headings = extract_vulnerability_headings_from_result(path)
    active = bool(lifecycle["active"])
    if not active:
        role = str(lifecycle["status"])

    if related_to:
        supplement_signals.append(f"related_to:{related_to}")

    return {
        "filename": filename,
        "role": role,
        "related_to": related_to,
        "lifecycle_status": lifecycle["status"],
        "active": active,
        "taskable": active and role != "supplement",
        "delivery_bucket": (
            lifecycle["delivery_bucket"]
            if not active else
            "results" if role != "supplement" else "result_supplements"
        ),
        "inference_signals": supplement_signals + list(lifecycle["signals"]),
        "vulnerability_headings": vulnerability_headings,
        "multi_finding": len(vulnerability_headings) > 1,
    }


def build_result_relations_manifest(
    results_dir: str | Path,
    summary_file: str | Path | None = None,
) -> dict[str, object]:
    all_results = list_result_report_files(results_dir)
    summary_selected = (
        extract_final_result_files_from_summary(summary_file, all_results)
        if summary_file else []
    )
    summary_refs = (
        extract_all_result_references_from_summary(summary_file, all_results)
        if summary_file else []
    )

    results_path = Path(results_dir)
    entries = [
        _infer_result_relationship(results_path / name)
        for name in all_results
    ]
    entry_by_name = {str(item["filename"]): item for item in entries}

    if summary_selected:
        final_results = list(summary_selected)
        for ref in summary_refs:
            entry = entry_by_name.get(ref)
            if not entry:
                continue
            if entry.get("role") == "supplement" and ref not in final_results:
                final_results.append(ref)
        selection_source = "summary_vulnerability_table"
    else:
        final_results = list(all_results)
        selection_source = "all_result_files"

    active_names = {
        str(item["filename"])
        for item in entries
        if bool(item.get("active", True))
    }
    final_results = [name for name in final_results if name in active_names]
    final_set = set(final_results)
    taskable_results = [
        name for name in final_results
        if entry_by_name.get(name, {}).get("taskable", True)
    ]
    supplemental_results = [
        name for name in final_results
        if not entry_by_name.get(name, {}).get("taskable", True)
    ]
    excluded_results = [name for name in all_results if name not in final_set]
    inactive_results = [
        name for name in all_results
        if name not in active_names
    ]

    return {
        "results_dir": str(results_path),
        "summary_file": str(summary_file) if summary_file else "",
        "all_results": all_results,
        "final_results": final_results,
        "taskable_results": taskable_results,
        "supplemental_results": supplemental_results,
        "excluded_results": excluded_results,
        "inactive_results": inactive_results,
        "selection_source": selection_source,
        "relationships": entries,
    }


def result_relations_manifest_path(working_dir: str | Path) -> Path:
    return Path(working_dir) / "_meta" / "result_relations_manifest.json"


def sync_result_relations_manifest(
    working_dir: str | Path,
    results_dir: str | Path,
    summary_file: str | Path | None = None,
) -> dict[str, object]:
    manifest = build_result_relations_manifest(results_dir, summary_file)
    manifest["working_dir"] = str(Path(working_dir))
    write_json(result_relations_manifest_path(working_dir), manifest)
    return manifest


def results_manifest_path(working_dir: str | Path) -> Path:
    return Path(working_dir) / "_meta" / "results_manifest.json"


def coverage_ledger_path(working_dir: str | Path) -> Path:
    return Path(working_dir) / "_meta" / "coverage_ledger.json"


def extract_data_flow_paths_from_task(task_file: str | Path | None) -> list[str]:
    """Return existing data-flow markdown files referenced by task.md."""
    if not task_file:
        return []
    task_path = Path(task_file)
    task_text = _read_text_if_exists(task_path)
    if not task_text:
        return []
    candidates: list[Path] = []
    for raw in _TASK_DATAFLOW_PATH_RE.findall(task_text):
        raw_path = Path(raw.strip())
        if raw_path.is_absolute():
            candidate = raw_path
        else:
            candidate = task_path.parent / raw_path
        if candidate.is_file() and candidate not in candidates:
            candidates.append(candidate)
    return [str(item) for item in candidates]


def _extract_declared_counts(task_text: str, data_flow_text: str = "") -> dict[str, int]:
    text = f"{task_text}\n{data_flow_text}"
    counts = {"input": 0, "export": 0, "used": 0, "cleaned": 0, "star": 0}
    for key, pattern in _TASK_COUNT_PATTERNS.items():
        match = pattern.search(text)
        if match:
            with_count = int(match.group(1))
            counts[key] = with_count
    counts["star"] = len([
        line for line in text.splitlines()
        if "★" in line or "关键发现" in line
    ])
    return counts


def extract_data_flow_obligations(
    content: str,
    *,
    source_file: str = "",
) -> list[dict[str, object]]:
    """Extract endpoint-level obligations from the original data-flow report."""
    entries: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for lineno, raw_line in enumerate((content or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        input_match = _DATAFLOW_INPUT_HEADING_RE.match(line)
        if input_match:
            number = int(input_match.group(1))
            label = _clean_obligation_label(input_match.group(2))
            value = f"INPUT-{number}: {label}" if label else f"INPUT-{number}"
            _append_data_flow_obligation(
                entries,
                seen,
                kind="input",
                value=value,
                source_file=source_file,
                source_line=lineno,
                target=f"INPUT-{number}",
                raw_line=line,
            )
            continue

        if "★" in line or "关键发现" in line:
            value = _clean_obligation_label(re.sub(r"^#+\s*", "", line))
            _append_data_flow_obligation(
                entries,
                seen,
                kind="star",
                value=value,
                source_file=source_file,
                source_line=lineno,
                target="STAR",
                raw_line=line,
            )

        upper = line.upper()
        if "EXPORT" in upper and ("🟡" in line or "@" in line or "调用" in line):
            target = _extract_endpoint_target_from_line(line)
            value = _format_dataflow_endpoint_value(target, line)
            _append_data_flow_obligation(
                entries,
                seen,
                kind="export",
                value=value,
                source_file=source_file,
                source_line=lineno,
                target=target,
                raw_line=line,
            )
        if "USED" in upper and ("📌" in line or "@" in line or "USED" in upper):
            target = _extract_used_target_from_line(line)
            value = _format_dataflow_endpoint_value(target, line)
            _append_data_flow_obligation(
                entries,
                seen,
                kind="used",
                value=value,
                source_file=source_file,
                source_line=lineno,
                target=target,
                raw_line=line,
            )
        if "CLEANED" in upper:
            target = _extract_endpoint_target_from_line(line) or "CLEANED"
            value = _format_dataflow_endpoint_value(target, line)
            _append_data_flow_obligation(
                entries,
                seen,
                kind="cleaned",
                value=value,
                source_file=source_file,
                source_line=lineno,
                target=target,
                raw_line=line,
            )
    return entries


def _append_data_flow_obligation(
    entries: list[dict[str, object]],
    seen: set[tuple[str, str, str]],
    *,
    kind: str,
    value: str,
    source_file: str,
    source_line: int,
    target: str,
    raw_line: str,
) -> None:
    value = _clean_obligation_label(value)
    if not value:
        return
    key = (kind, _normalize_endpoint_value(kind, value), str(source_line))
    if key in seen:
        return
    seen.add(key)
    entries.append({
        "kind": kind,
        "value": value,
        "target": _clean_obligation_label(target) or value,
        "source_file": source_file,
        "source_line": source_line,
        "raw_line": raw_line[:500],
        "risk": _infer_obligation_risk(kind, value, raw_line=raw_line),
        "source": "data_flow_file",
    })


def _extract_endpoint_target_from_line(line: str) -> str:
    for token in _BACKTICK_TOKEN_RE.findall(line):
        cleaned = _clean_obligation_label(token)
        if cleaned and not cleaned.lower().startswith("result_"):
            return cleaned
    arrow = line.split("→", 1)[1] if "→" in line else line
    call_match = _FUNCTION_CALL_RE.search(arrow)
    if call_match:
        return call_match.group(1)
    ident_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b", arrow)
    return ident_match.group(1) if ident_match else _clean_obligation_label(arrow[:120])


def _extract_used_target_from_line(line: str) -> str:
    for token in _BACKTICK_TOKEN_RE.findall(line):
        cleaned = _clean_obligation_label(token)
        if cleaned:
            return cleaned
    danger = re.search(
        r"\b(RAW_U(?:8|16|32|64)|MBUF_[A-Za-z0-9_]+|VOS_[A-Za-z0-9_]+|"
        r"IPSEC_[A-Za-z0-9_]+|SSP_Debug|memcpy_s?|memset_s?|VRP_[A-Za-z0-9_]+|"
        r"[A-Za-z_][A-Za-z0-9_]{2,}\[[^\]\n]{1,40}\])\b",
        line,
    )
    if danger:
        return danger.group(1)
    return _extract_endpoint_target_from_line(line)


def _format_dataflow_endpoint_value(target: str, line: str) -> str:
    target = _clean_obligation_label(target)
    line_ref = _extract_line_ref(line)
    if target and line_ref:
        return f"{target}@{line_ref}"
    return target or _clean_obligation_label(line[:160])


def _extract_line_ref(line: str) -> str:
    match = _LINE_REF_RE.search(line)
    if not match:
        return ""
    number = match.group(1) or match.group(2)
    return f"L{number}"


def _clean_obligation_label(value: str) -> str:
    text = str(value or "").strip()
    text = re.sub(r"^[├└│\-\s>]+", "", text)
    text = re.sub(r"[🔴🟡📌✅⚠️⏭️📎]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:220]


def _infer_obligation_risk(kind: str, value: str, *, raw_line: str = "") -> str:
    text = str(value or "")
    context = f"{text}\n{raw_line or ''}"
    if kind == "star":
        return "critical"
    if kind == "cleaned":
        return "high" if "CLEANED=0" in context.upper() or "无数据清洗" in context else "medium"
    if kind == "export":
        return "high" if _DANGEROUS_ENDPOINT_RE.search(text) else "medium"
    if kind == "used":
        high_risk_used = re.search(
            r"(?i)(memcpy|memset|MBUF_MakeMemoryContinuous|MBUF_CutPart|"
            r"CreateControlInfo|CheckSum|malloc|free|长度|越界|拷贝|复制|写入|"
            r"RAW_U(?:16|32|64)\s*\([^)\n]+\)\s*=(?!=))",
            context,
        )
        return "high" if high_risk_used else "medium"
    if kind == "input":
        return "medium"
    return "low"


def build_results_manifest(
    working_dir: str | Path,
    results_dir: str | Path,
    summary_file: str | Path | None = None,
) -> dict[str, object]:
    relations = build_result_relations_manifest(results_dir, summary_file)
    entries = list(relations.get("relationships") or [])
    return {
        "schema_version": 1,
        "working_dir": str(Path(working_dir)),
        "results_dir": str(Path(results_dir)),
        "summary_file": str(summary_file) if summary_file else "",
        "total_result_files": len(relations.get("all_results") or []),
        "active_result_count": len([
            item for item in entries if bool(item.get("active", True))
        ]),
        "inactive_result_count": len(relations.get("inactive_results") or []),
        "taskable_result_count": len(relations.get("taskable_results") or []),
        "supplemental_result_count": len(relations.get("supplemental_results") or []),
        "taskable_results": relations.get("taskable_results") or [],
        "supplemental_results": relations.get("supplemental_results") or [],
        "inactive_results": relations.get("inactive_results") or [],
        "excluded_results": relations.get("excluded_results") or [],
        "entries": entries,
    }


def build_coverage_ledger(
    working_dir: str | Path,
    results_dir: str | Path,
    summary_file: str | Path | None = None,
    task_file: str | Path | None = None,
    supporting_docs_dir: str | Path | None = None,
) -> dict[str, object]:
    all_results = list_result_report_files(results_dir)
    summary_refs = (
        extract_all_result_references_from_summary(summary_file, all_results)
        if summary_file else []
    )
    final_selection = classify_final_result_files(results_dir, summary_file)
    referenced_set = set(summary_refs)
    active_set = {
        str(item.get("filename"))
        for item in final_selection.get("relationships", [])
        if bool(item.get("active", True))
    }
    endpoint_audit = build_endpoint_audit(
        results_dir,
        summary_file,
        supporting_docs_dir=supporting_docs_dir,
    )
    task_text = _read_text_if_exists(task_file)
    data_flow_files = extract_data_flow_paths_from_task(task_file)
    data_flow_texts: list[str] = []
    data_flow_obligations: list[dict[str, object]] = []
    for data_flow_file in data_flow_files:
        text = _read_text_if_exists(data_flow_file)
        if not text:
            continue
        data_flow_texts.append(text)
        data_flow_obligations.extend(
            extract_data_flow_obligations(text, source_file=data_flow_file)
        )
    data_flow_text = "\n".join(data_flow_texts)
    task_mentions = extract_endpoint_mentions_from_text(task_text)
    data_flow_mentions = extract_endpoint_mentions_from_text(data_flow_text)
    source_mentions = (
        task_mentions
        if data_flow_obligations else
        _merge_endpoint_mentions(task_mentions, data_flow_mentions)
    )
    declared_counts = _extract_declared_counts(task_text, data_flow_text)
    obligations = build_coverage_obligations(
        task_mentions=source_mentions,
        endpoint_audit=endpoint_audit,
        data_flow_obligations=data_flow_obligations,
        declared_counts=declared_counts,
    )
    return {
        "schema_version": 1,
        "working_dir": str(Path(working_dir)),
        "results_dir": str(Path(results_dir)),
        "summary_file": str(summary_file) if summary_file else "",
        "task_file": str(task_file) if task_file else "",
        "result_files": all_results,
        "summary_result_references": summary_refs,
        "active_results": sorted(active_set),
        "final_results": final_selection.get("final_results") or [],
        "taskable_results": final_selection.get("taskable_results") or [],
        "inactive_results": final_selection.get("inactive_results") or [],
        "unreferenced_active_results": sorted(active_set - referenced_set),
        "missing_referenced_results": sorted(referenced_set - set(all_results)),
        "endpoint_audit": endpoint_audit,
        "task_endpoint_mentions": task_mentions,
        "data_flow_files": data_flow_files,
        "data_flow_endpoint_mentions": data_flow_mentions,
        "coverage_obligations": obligations,
        "notes": [
            "This ledger is framework-generated from result files and summary references.",
            "Coverage obligations are extracted from the task/data-flow file and are the stable closure checklist across cycles.",
            "Endpoint audit is a deterministic scaffold; advisors should still verify source-level coverage.",
        ],
    }


def build_endpoint_audit(
    results_dir: str | Path,
    summary_file: str | Path | None = None,
    *,
    supporting_docs_dir: str | Path | None = None,
) -> dict[str, object]:
    summary_mentions = (
        extract_endpoint_mentions_from_text(_read_text(summary_file))
        if summary_file and Path(summary_file).is_file() else
        extract_endpoint_mentions_from_text("")
    )
    result_mentions: dict[str, dict[str, list[str]]] = {}
    supporting_doc_mentions: dict[str, dict[str, list[str]]] = {}
    aggregate = {
        "input_ids": list(summary_mentions["input_ids"]),
        "export_symbols": list(summary_mentions["export_symbols"]),
        "used_symbols": list(summary_mentions["used_symbols"]),
        "cleaned_symbols": list(summary_mentions["cleaned_symbols"]),
        "star_findings": list(summary_mentions["star_findings"]),
        "code_symbols": list(summary_mentions.get("code_symbols") or []),
    }

    results_path = Path(results_dir)
    for filename in list_result_report_files(results_path):
        path = results_path / filename
        mentions = extract_endpoint_mentions_from_text(_read_text(path))
        result_mentions[filename] = mentions
        for key, values in mentions.items():
            if key not in aggregate:
                continue
            aggregate[key].extend(values)

    supporting_path = Path(supporting_docs_dir) if supporting_docs_dir else None
    if supporting_path and supporting_path.is_dir():
        for filename in list_supporting_markdown_files(supporting_path):
            path = supporting_path / filename
            mentions = extract_endpoint_mentions_from_text(_read_text(path))
            supporting_doc_mentions[filename] = mentions
            for key, values in mentions.items():
                if key not in aggregate:
                    continue
                aggregate[key].extend(values)

    return {
        "schema_version": 1,
        "extractor": "regex_v1",
        "summary_mentions": summary_mentions,
        "result_mentions": result_mentions,
        "supporting_doc_mentions": supporting_doc_mentions,
        "aggregate_mentions": {
            "input_ids": _dedupe_sorted(aggregate["input_ids"]),
            "export_symbols": _dedupe_sorted(aggregate["export_symbols"]),
            "used_symbols": _dedupe_sorted(aggregate["used_symbols"]),
            "cleaned_symbols": _dedupe_sorted(aggregate["cleaned_symbols"]),
            "star_findings": _dedupe_preserve_order(aggregate["star_findings"]),
            "code_symbols": _dedupe_sorted(aggregate["code_symbols"]),
        },
    }


def build_coverage_obligations(
    *,
    task_mentions: dict[str, list[str]],
    endpoint_audit: dict[str, object],
    data_flow_obligations: list[dict[str, object]] | None = None,
    declared_counts: dict[str, int] | None = None,
) -> dict[str, object]:
    """Build a stable task-derived closure checklist for global review."""
    entries: list[dict[str, object]] = []
    by_kind: dict[str, dict[str, int]] = {}
    seen_keys: set[tuple[str, str]] = set()

    for raw_entry in data_flow_obligations or []:
        if not isinstance(raw_entry, dict):
            continue
        kind = str(raw_entry.get("kind") or "").strip().lower()
        if kind not in _OBLIGATION_KEYS:
            continue
        value = str(raw_entry.get("value") or "").strip()
        if not value:
            continue
        key = (kind, _normalize_endpoint_value(kind, value))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        aliases = [
            str(raw_entry.get("target") or ""),
            value.split("@", 1)[0],
            _extract_line_ref(str(raw_entry.get("raw_line") or "")),
        ]
        evidence_sources = _find_endpoint_evidence_sources(
            kind=kind,
            value=value,
            endpoint_audit=endpoint_audit,
            aliases=aliases,
        )
        status = "documented" if evidence_sources else "open"
        entry = {
            "id": _coverage_obligation_id(kind, value, len(entries) + 1),
            "kind": kind,
            "label": _OBLIGATION_LABELS[kind],
            "value": value,
            "target": str(raw_entry.get("target") or ""),
            "risk": str(raw_entry.get("risk") or _infer_obligation_risk(kind, value)),
            "status": status,
            "documented": bool(evidence_sources),
            "evidence_sources": evidence_sources,
            "source": str(raw_entry.get("source") or "data_flow_file"),
            "source_file": str(raw_entry.get("source_file") or ""),
            "source_line": int(raw_entry.get("source_line") or 0),
        }
        entries.append(entry)
        stats = by_kind.setdefault(kind, {"total": 0, "documented": 0, "open": 0})
        stats["total"] += 1
        stats[status] += 1

    for kind, mention_key in _OBLIGATION_KEYS.items():
        values = task_mentions.get(mention_key) or []
        for index, raw_value in enumerate(values, start=1):
            value = str(raw_value).strip()
            if not value:
                continue
            key = (kind, _normalize_endpoint_value(kind, value))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            evidence_sources = _find_endpoint_evidence_sources(
                kind=kind,
                value=value,
                endpoint_audit=endpoint_audit,
            )
            status = "documented" if evidence_sources else "open"
            entry = {
                "id": _coverage_obligation_id(kind, value, index),
                "kind": kind,
                "label": _OBLIGATION_LABELS[kind],
                "value": value,
                "target": value,
                "risk": _infer_obligation_risk(kind, value),
                "status": status,
                "documented": bool(evidence_sources),
                "evidence_sources": evidence_sources,
                "source": "task_or_dataflow_mentions",
                "source_file": "",
                "source_line": 0,
            }
            entries.append(entry)
            stats = by_kind.setdefault(kind, {"total": 0, "documented": 0, "open": 0})
            stats["total"] += 1
            stats[status] += 1

    declared = dict(declared_counts or {})
    declared_total = sum(
        int(declared.get(key) or 0)
        for key in ("input", "export", "used", "cleaned", "star")
    )
    extracted_total = len(entries)

    return {
        "schema_version": 1,
        "source": "task_file_and_data_flow",
        "total": len(entries),
        "documented": len([item for item in entries if item["documented"]]),
        "open": len([item for item in entries if not item["documented"]]),
        "by_kind": by_kind,
        "quality": {
            "declared_counts": declared,
            "declared_total": declared_total,
            "extracted_total": extracted_total,
            "declared_extraction_ratio": (
                extracted_total / declared_total if declared_total else 1.0
            ),
            "data_flow_obligation_count": len(data_flow_obligations or []),
        },
        "entries": entries,
        "open_entries": [item for item in entries if not item["documented"]],
    }


def format_coverage_obligation_summary(
    coverage_ledger: dict[str, object] | None,
    *,
    max_open: int = 20,
) -> str:
    """Compact human-readable obligation summary for Worker/Advisor prompts."""
    if not coverage_ledger:
        return "(coverage ledger not available)"
    obligations = coverage_ledger.get("coverage_obligations") or {}
    if not isinstance(obligations, dict):
        return "(coverage obligations not available in ledger)"

    by_kind = obligations.get("by_kind") or {}
    quality = obligations.get("quality") or {}
    lines = [
        "## Coverage Obligation Ledger",
        (
            f"- total={int(obligations.get('total') or 0)}, "
            f"documented={int(obligations.get('documented') or 0)}, "
            f"open={int(obligations.get('open') or 0)}"
        ),
    ]
    if isinstance(quality, dict) and quality:
        declared_total = int(quality.get("declared_total") or 0)
        ratio = float(quality.get("declared_extraction_ratio") or 0.0)
        lines.append(
            f"- declared_total={declared_total}, extracted_total={int(quality.get('extracted_total') or 0)}, "
            f"declared_extraction_ratio={ratio:.2f}"
        )
    if isinstance(by_kind, dict):
        for kind in ("input", "export", "used", "cleaned", "star"):
            stats = by_kind.get(kind) or {}
            if not stats:
                continue
            lines.append(
                f"- {kind}: {int(stats.get('documented') or 0)}/"
                f"{int(stats.get('total') or 0)} documented, "
                f"open={int(stats.get('open') or 0)}"
            )

    open_entries = obligations.get("open_entries") or []
    if open_entries:
        lines.append("")
        lines.append(f"### Open obligations (first {max_open})")
        for item in open_entries[:max_open]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('id')}: {item.get('label')} "
                f"`{item.get('value')}` -> status={item.get('status')}"
                f", risk={item.get('risk') or 'medium'}"
            )
    return "\n".join(lines)


def _coverage_obligation_id(kind: str, value: str, index: int) -> str:
    normalized = _normalize_endpoint_value(kind, value)
    if kind == "star":
        digest = hashlib.sha1(normalized.encode("utf-8", errors="replace")).hexdigest()[:10]
        return f"STAR:{index:03d}:{digest}"
    token = re.sub(r"[^A-Za-z0-9_.:-]+", "_", normalized).strip("_")
    return f"{_OBLIGATION_LABELS.get(kind, kind.upper())}:{token[:96]}"


def _find_endpoint_evidence_sources(
    *,
    kind: str,
    value: str,
    endpoint_audit: dict[str, object],
    aliases: list[str] | None = None,
) -> list[str]:
    mention_key = _OBLIGATION_KEYS[kind]
    targets = [
        _normalize_endpoint_value(kind, item)
        for item in [value, *(aliases or [])]
        if str(item or "").strip()
    ]
    sources: list[str] = []

    summary_mentions = endpoint_audit.get("summary_mentions") or {}
    if _mentions_contain_any(summary_mentions, mention_key, targets, kind):
        sources.append("summary.md")

    for filename, mentions in (endpoint_audit.get("result_mentions") or {}).items():
        if _mentions_contain_any(mentions, mention_key, targets, kind):
            sources.append(f"results/{filename}")

    for filename, mentions in (endpoint_audit.get("supporting_doc_mentions") or {}).items():
        if _mentions_contain_any(mentions, mention_key, targets, kind):
            sources.append(f"supporting_docs/{filename}")

    return sources


def _mentions_contain(
    mentions: object,
    mention_key: str,
    normalized_target: str,
    kind: str,
) -> bool:
    if not isinstance(mentions, dict):
        return False
    values = mentions.get(mention_key) or []
    return normalized_target in {
        _normalize_endpoint_value(kind, str(value))
        for value in values
        if str(value).strip()
    }


def _mentions_contain_any(
    mentions: object,
    mention_key: str,
    normalized_targets: list[str],
    kind: str,
) -> bool:
    if not normalized_targets:
        return False
    if not isinstance(mentions, dict):
        return False
    raw_values = list(mentions.get(mention_key) or [])
    raw_values.extend(mentions.get("code_symbols") or [])
    normalized_values = {
        _normalize_endpoint_value(kind, str(value))
        for value in raw_values
        if str(value).strip()
    }
    targets = {item for item in normalized_targets if item}
    if normalized_values & targets:
        return True
    # For data-flow entries like MBUF_Copy@L1234, allow a documented source
    # to mention the symbol without the exact data-flow line suffix.
    base_targets = {
        item.split("@", 1)[0].strip()
        for item in targets
        if "@" in item
    }
    return bool(base_targets & normalized_values)


def _normalize_endpoint_value(kind: str, value: str) -> str:
    text = str(value or "").strip()
    if kind == "input":
        return _canonical_input_ref(text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    if kind == "star":
        return text.lower()[:220]
    return text


def sync_structured_result_manifests(
    working_dir: str | Path,
    results_dir: str | Path,
    summary_file: str | Path | None = None,
    task_file: str | Path | None = None,
    supporting_docs_dir: str | Path | None = None,
) -> dict[str, object]:
    results_manifest = build_results_manifest(working_dir, results_dir, summary_file)
    coverage_ledger = build_coverage_ledger(
        working_dir,
        results_dir,
        summary_file,
        task_file=task_file,
        supporting_docs_dir=supporting_docs_dir,
    )
    write_json(results_manifest_path(working_dir), results_manifest)
    write_json(coverage_ledger_path(working_dir), coverage_ledger)
    return {
        "results_manifest": results_manifest,
        "coverage_ledger": coverage_ledger,
    }


def list_final_result_report_files(
    results_dir: str | Path,
    summary_file: str | Path | None = None,
) -> list[str]:
    selection = classify_final_result_files(results_dir, summary_file)
    return list(selection["taskable_results"])


def classify_final_result_files(
    results_dir: str | Path,
    summary_file: str | Path | None = None,
) -> dict[str, object]:
    return build_result_relations_manifest(results_dir, summary_file)


def list_supporting_markdown_files(dir_path: str | Path) -> list[str]:
    path = Path(dir_path)
    if not path.is_dir():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file()
        and item.suffix == ".md"
        and item.name != "summary.md"
        and not is_result_report_filename(item.name)
    )


def split_markdown_outputs(dir_path: str | Path) -> tuple[list[str], list[str]]:
    return list_result_report_files(dir_path), list_supporting_markdown_files(dir_path)
