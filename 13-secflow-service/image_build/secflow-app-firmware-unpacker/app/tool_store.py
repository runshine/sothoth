"""Python tool repository helpers for firmware unpacking."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

MIN_TOOL_MATCH_SCORE = 30


def _parse_list(value: str) -> list[str]:
    cleaned = str(value or "").strip()
    if not cleaned:
        return []
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    items: list[str] = []
    for item in cleaned.split(","):
        token = item.strip().strip("\"'").lower()
        if token:
            items.append(token)
    return items


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return slug.strip("-") or "generic-tool"


def _comment_header_lines(tool_path: Path) -> list[str]:
    lines: list[str] = []
    try:
        with tool_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")
                stripped = line.strip()
                if not stripped:
                    if lines:
                        break
                    continue
                if stripped.startswith("#!"):
                    continue
                if not stripped.startswith("#"):
                    if lines:
                        break
                    return []
                lines.append(stripped[1:].strip())
    except Exception:
        return []
    return lines


def parse_tool_metadata(tool_path: Path) -> dict[str, Any]:
    stem = tool_path.stem
    meta: dict[str, Any] = {
        "path": str(tool_path),
        "filename": tool_path.name,
        "name": stem,
        "format_id": stem,
        "description": "",
        "extensions": [],
        "magic_hex": "",
        "keywords": [item for item in re.split(r"[^a-z0-9]+", stem.lower()) if item],
        "binwalk_sigs": [],
    }
    for line in _comment_header_lines(tool_path):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if normalized_key in {"extensions", "keywords", "binwalk_sigs"}:
            meta[normalized_key] = _parse_list(normalized_value)
        elif normalized_key == "magic_hex":
            meta[normalized_key] = normalized_value.lower().replace(" ", "")
        elif normalized_key in {"name", "format_id", "description"}:
            meta[normalized_key] = normalized_value
    return meta


def list_python_tools(tools_dir: Path) -> list[dict[str, Any]]:
    tools_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for tool_path in sorted(tools_dir.glob("*.py")):
        items.append(parse_tool_metadata(tool_path))
    return items


def compute_family_id(features: dict[str, Any]) -> str:
    parts = [
        str(features.get("fmt") or "").strip().lower(),
        str(features.get("ext") or "").strip().lower(),
        str(features.get("magic_hex") or "").strip().lower()[:8],
    ]
    for signature in features.get("binwalk_sigs") or []:
        token = _slugify(signature)[:32]
        if token:
            parts.append(token)
            break
    return _slugify("-".join([part for part in parts if part and part != "unknown"]))


def match_python_tool(features: dict[str, Any], tools_dir: Path) -> tuple[dict[str, Any] | None, int, dict[str, Any]]:
    feat_ext = str(features.get("ext") or "").lower()
    feat_ext2 = str(features.get("ext2") or "").lower()
    feat_magic = str(features.get("magic_hex") or "").lower()[:8]
    feat_fname = str(features.get("filename") or "").lower()
    feat_sigs = [str(item).lower() for item in features.get("binwalk_sigs") or []]
    search_text = feat_fname + " " + " ".join(feat_sigs)

    best_tool = None
    best_score = 0
    best_match: dict[str, Any] = {"reasons": []}

    for meta in list_python_tools(tools_dir):
        score = 0
        reasons: list[str] = []
        magic = str(meta.get("magic_hex") or "").lower()
        if magic and feat_magic and (feat_magic.startswith(magic) or magic.startswith(feat_magic)):
            score += 60
            reasons.append(f"magic:{magic}")
        for ext in meta.get("extensions") or []:
            if ext and (feat_ext == ext or feat_ext2 == ext or feat_ext2.endswith(ext)):
                score += 25
                reasons.append(f"ext:{ext}")
                break
        for signature in meta.get("binwalk_sigs") or []:
            signature_text = str(signature).lower()
            if signature_text and any(signature_text in feature_sig for feature_sig in feat_sigs):
                score += 20
                reasons.append(f"binwalk:{signature_text}")
                break
        keyword_hits = [keyword for keyword in meta.get("keywords") or [] if keyword and keyword in search_text]
        if keyword_hits:
            score += min(15, len(keyword_hits) * 5)
            reasons.append(f"keywords:{','.join(keyword_hits[:3])}")
        if score > best_score:
            best_tool = meta
            best_score = score
            best_match = {"reasons": reasons}

    if best_tool is None or best_score < MIN_TOOL_MATCH_SCORE:
        return None, best_score, best_match
    return best_tool, best_score, best_match


__all__ = [
    "compute_family_id",
    "list_python_tools",
    "match_python_tool",
    "parse_tool_metadata",
]
