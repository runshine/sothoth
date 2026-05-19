from __future__ import annotations

import re
from pathlib import Path

from app.pi_vuln_core.utils.file_ops import write_json

_RESULT_REPORT_RE = re.compile(r"^result_(\d+)\.md$")
_RESULT_REF_RE = re.compile(r"\bresult_\d+\.md\b")
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


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


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


def sync_structured_result_manifests(
    working_dir: str | Path,
    results_dir: str | Path,
    summary_file: str | Path | None = None,
    task_file: str | Path | None = None,
    supporting_docs_dir: str | Path | None = None,
) -> dict[str, object]:
    results_manifest = build_results_manifest(working_dir, results_dir, summary_file)
    write_json(results_manifest_path(working_dir), results_manifest)
    return {
        "results_manifest": results_manifest,
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
