"""Stage: write a bounded reusable-skill candidate from a successful generic run."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "generic-firmware"


def _summary_excerpt(output_path: str) -> str:
    summary = Path(output_path) / "summary.txt"
    raw_summary = summary.read_text(encoding="utf-8", errors="replace") if summary.is_file() else ""
    summary_lines: list[str] = []
    for line in raw_summary.splitlines():
        compact = " ".join(line.split())
        if compact:
            summary_lines.append(compact[:500])
        if len(summary_lines) >= 80:
            break
    summary_text = "\n".join(summary_lines)
    if len(raw_summary.splitlines()) > len(summary_lines) or len(raw_summary) > len(summary_text):
        summary_text += "\n[summary truncated for reusable skill size]"
    return summary_text


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    nodes = nodes or {}
    review = str((nodes.get("generic_reviewer") or {}).get("output") or "")
    print("AGENTFLOW_PROGRESS stage=skill_author event=start", flush=True)
    if "AGENTFLOW_REVIEW_SUCCESS" not in review:
        print("AGENTFLOW_PROGRESS stage=skill_author event=skip reason=NO_GENERIC_SUCCESS", flush=True)
        print("SKIPPED_NO_GENERIC_SUCCESS")
        return

    feature_payload = json.loads(Path(payload["feature_match_output_file"]).read_text(encoding="utf-8"))
    features = feature_payload.get("features") or {}
    family_id = str(features.get("family_id") or "generic-firmware")
    slug = _slug(family_id)
    ext = str(features.get("ext") or features.get("ext2") or "").strip() or ".bin"
    magic_hex = str(features.get("magic_hex") or "").strip()

    raw_sigs: list[str] = []
    seen_sigs: set[str] = set()
    for item in features.get("binwalk_sigs") or []:
        sig = " ".join(str(item).split())[:60]
        if sig and sig not in seen_sigs:
            raw_sigs.append(sig)
            seen_sigs.add(sig)
        if len(raw_sigs) >= 8:
            break
    sigs = ", ".join(raw_sigs) or "firmware"

    doc = f"""---
name: {slug} unpack
description: Candidate firmware unpacking guidance generated from a successful AgentFlow run
format_id: {slug}
extensions: {ext}
magic_hex: {magic_hex}
keywords: firmware, unpack, {slug}
binwalk_sigs: {sigs}
skill_status: candidate
skill_version: 1
family_id: {family_id}
promotion_success_count: 0
promotion_threshold: 5
tools: file, binwalk, dd, readelf, strings
---

Use this skill for firmware images with the same recognition signals. Re-run binwalk, extract the embedded component at the detected offset, preserve the original header when present, and write summary.txt with extracted artifacts and reuse notes.

Source summary:
{_summary_excerpt(payload["output_path"])}
"""
    output_file = Path(payload["skill_author_output_file"])
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(doc, encoding="utf-8")
    print(f"AGENTFLOW_PROGRESS stage=skill_author event=finish output_file={output_file}", flush=True)
    print(f"AGENTFLOW_SKILL_AUTHOR_WRITTEN path={output_file}")

