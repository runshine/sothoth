"""Skill repository helpers for firmware unpacking self-evolution."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SKILL_STATUS_ACTIVE = "active"
SKILL_STATUS_CANDIDATE = "candidate"
SKILL_STATUS_ARCHIVED = "archived"
DEFAULT_PROMOTION_THRESHOLD = 5
MAX_SKILL_PROMPT_CHARS = 20_000
MAX_SKILL_PROMPT_LINES = 200
MAX_SKILL_PROMPT_LINE_CHARS = 500
MAX_SKILL_LIST_ITEMS = 20
MAX_SKILL_LIST_ITEM_CHARS = 80


def _parse_list(value: str) -> list[str]:
    cleaned = str(value or "").strip()
    if not cleaned:
        return []
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return [item.strip().lower() for item in cleaned.split(",") if item.strip()]


def _parse_int(value: str | None, default: int) -> int:
    try:
        return int(str(value or "").strip())
    except Exception:
        return default


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return slug.strip("-") or "generic-firmware"


def parse_skill_metadata(skill_path: Path, include_prompt: bool = False) -> dict[str, Any]:
    raw = skill_path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n?(.*)$", raw, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid skill definition: {skill_path}")

    header = match.group(1)
    body = match.group(2).strip()
    meta: dict[str, Any] = {
        "path": str(skill_path),
        "filename": skill_path.name,
        "name": skill_path.stem,
        "description": "",
        "format_id": skill_path.stem,
        "extensions": [],
        "magic_hex": "",
        "keywords": [],
        "binwalk_sigs": [],
        "skill_status": SKILL_STATUS_CANDIDATE,
        "skill_version": 1,
        "family_id": skill_path.stem,
        "promotion_success_count": 0,
        "promotion_threshold": DEFAULT_PROMOTION_THRESHOLD,
        "source_run_id": "",
        "source_node_id": "",
        "evaluation_batch": "",
        "tools": [],
    }
    for line in header.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if key in {"extensions", "keywords", "binwalk_sigs", "tools"}:
            meta[key] = _parse_list(value)
        elif key == "magic_hex":
            meta[key] = value.lower().replace(" ", "")
        elif key == "skill_version":
            meta[key] = _parse_int(value, 1)
        elif key == "promotion_success_count":
            meta[key] = _parse_int(value, 0)
        elif key == "promotion_threshold":
            meta[key] = _parse_int(value, DEFAULT_PROMOTION_THRESHOLD)
        else:
            meta[key] = value
    if include_prompt:
        meta["system_prompt"] = body
    return meta


def list_skills(skills_dir: Path, *, statuses: set[str] | None = None, include_prompt: bool = False) -> list[dict[str, Any]]:
    skills_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for skill_path in sorted(skills_dir.glob("*.md")):
        try:
            meta = parse_skill_metadata(skill_path, include_prompt=include_prompt)
        except Exception:
            continue
        if statuses and str(meta.get("skill_status") or "").strip().lower() not in statuses:
            continue
        items.append(meta)
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


def match_skill(features: dict[str, Any], skills_dir: Path) -> tuple[dict[str, Any] | None, int, dict[str, Any]]:
    feat_ext = str(features.get("ext") or "").lower()
    feat_ext2 = str(features.get("ext2") or "").lower()
    feat_magic = str(features.get("magic_hex") or "").lower()[:8]
    feat_fname = str(features.get("filename") or "").lower()
    feat_sigs = [str(item).lower() for item in features.get("binwalk_sigs") or []]
    search_text = feat_fname + " " + " ".join(feat_sigs)

    active_skills = list_skills(skills_dir, statuses={SKILL_STATUS_ACTIVE}, include_prompt=True)
    candidate_skills = list_skills(skills_dir, statuses={SKILL_STATUS_CANDIDATE}, include_prompt=True)

    best_skill = None
    best_score = 0
    best_match: dict[str, Any] = {"matched_status": None, "reasons": []}

    def _score_one(meta: dict[str, Any], status_label: str) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        magic = str(meta.get("magic_hex") or "").lower()
        if magic and feat_magic:
            if feat_magic.startswith(magic) or magic.startswith(feat_magic):
                score += 60
                reasons.append(f"magic:{magic}")
        for ext in meta.get("extensions") or []:
            if ext and (feat_ext == ext or feat_ext2 == ext or feat_ext2.endswith(ext)):
                score += 25
                reasons.append(f"ext:{ext}")
                break
        for signature in meta.get("binwalk_sigs") or []:
            if any(signature in feature_sig for feature_sig in feat_sigs):
                score += 20
                reasons.append(f"binwalk:{signature}")
                break
        keyword_hits = [keyword for keyword in meta.get("keywords") or [] if keyword and keyword in search_text]
        if keyword_hits:
            score += min(15, len(keyword_hits) * 5)
            reasons.append(f"keywords:{','.join(keyword_hits[:3])}")
        if status_label == SKILL_STATUS_ACTIVE:
            score += 5
        return score, reasons

    for status_label, candidates in ((SKILL_STATUS_ACTIVE, active_skills), (SKILL_STATUS_CANDIDATE, candidate_skills)):
        for meta in candidates:
            score, reasons = _score_one(meta, status_label)
            if score > best_score:
                best_skill = meta
                best_score = score
                best_match = {
                    "matched_status": status_label,
                    "reasons": reasons,
                }
        if best_skill and best_score >= 50 and status_label == SKILL_STATUS_ACTIVE:
            break

    if best_skill is None or best_score < 50:
        return None, best_score, best_match
    return best_skill, best_score, best_match


def _serialize_frontmatter(meta: dict[str, Any]) -> str:
    ordered_keys = [
        "name",
        "description",
        "format_id",
        "extensions",
        "magic_hex",
        "keywords",
        "binwalk_sigs",
        "skill_status",
        "skill_version",
        "family_id",
        "promotion_success_count",
        "promotion_threshold",
        "source_run_id",
        "source_node_id",
        "evaluation_batch",
        "tools",
    ]
    lines: list[str] = ["---"]
    for key in ordered_keys:
        value = meta.get(key)
        if key in {"extensions", "keywords", "binwalk_sigs", "tools"}:
            value = ", ".join(value or [])
        lines.append(f"{key}: {value}")
    lines.append("---")
    return "\n".join(lines)


def validate_skill_document(raw: str) -> dict[str, Any]:
    temp = Path("/tmp/__skill_validation__.md")
    temp.write_text(raw, encoding="utf-8")
    try:
        meta = parse_skill_metadata(temp, include_prompt=True)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    required_text = ["name", "description", "format_id", "family_id", "magic_hex"]
    for field in required_text:
        if not str(meta.get(field) or "").strip():
            raise ValueError(f"missing required field: {field}")
    for field in ("extensions", "keywords", "binwalk_sigs"):
        if not meta.get(field):
            raise ValueError(f"missing required field: {field}")
    if not str(meta.get("system_prompt") or "").strip():
        raise ValueError("skill body is empty")
    return meta


def _write_skill(path: Path, meta: dict[str, Any], system_prompt: str) -> None:
    document = _serialize_frontmatter(meta) + "\n\n" + system_prompt.strip() + "\n"
    path.write_text(document, encoding="utf-8")


def _sanitize_system_prompt(system_prompt: str) -> str:
    lines = []
    for line in str(system_prompt or "").splitlines():
        compact = " ".join(line.split())
        if compact:
            lines.append(compact[:MAX_SKILL_PROMPT_LINE_CHARS])
        if len(lines) >= MAX_SKILL_PROMPT_LINES:
            break
    sanitized = "\n".join(lines).strip()
    truncated = (
        len(lines) < len(str(system_prompt or "").splitlines())
        or len(str(system_prompt or "")) > len(sanitized)
    )
    if len(sanitized) > MAX_SKILL_PROMPT_CHARS:
        sanitized = sanitized[:MAX_SKILL_PROMPT_CHARS].rstrip()
        truncated = True
    if truncated:
        sanitized = sanitized.rstrip() + "\n[skill body truncated for safe reuse]"
    return sanitized or "Reusable firmware unpacking guidance was truncated; inspect source run artifacts before promotion."


def _sanitize_skill_metadata(meta: dict[str, Any]) -> None:
    for key in ("extensions", "keywords", "binwalk_sigs", "tools"):
        cleaned = []
        seen = set()
        for item in meta.get(key) or []:
            value = " ".join(str(item).split())[:MAX_SKILL_LIST_ITEM_CHARS]
            if not value or value.lower() in seen:
                continue
            cleaned.append(value)
            seen.add(value.lower())
            if len(cleaned) >= MAX_SKILL_LIST_ITEMS:
                break
        meta[key] = cleaned


def save_candidate_skill(skills_dir: Path, raw_document: str, fallback_meta: dict[str, Any]) -> dict[str, Any]:
    meta = validate_skill_document(raw_document)
    family_id = _slugify(meta.get("family_id") or fallback_meta.get("family_id"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    meta["family_id"] = family_id
    meta["skill_status"] = SKILL_STATUS_CANDIDATE
    meta["promotion_success_count"] = 0
    meta["promotion_threshold"] = DEFAULT_PROMOTION_THRESHOLD
    meta["source_run_id"] = str(fallback_meta.get("source_run_id") or meta.get("source_run_id") or "")
    meta["source_node_id"] = str(fallback_meta.get("source_node_id") or meta.get("source_node_id") or "")
    meta["evaluation_batch"] = str(fallback_meta.get("evaluation_batch") or meta.get("evaluation_batch") or "")
    _sanitize_skill_metadata(meta)
    meta["system_prompt"] = _sanitize_system_prompt(str(meta.get("system_prompt") or ""))
    existing_versions = [
        int(item.get("skill_version") or 0)
        for item in list_skills(skills_dir)
        if str(item.get("family_id") or "") == family_id
    ]
    meta["skill_version"] = max(existing_versions or [0]) + 1
    target = skills_dir / f"{family_id}__candidate__{timestamp}.md"
    _write_skill(target, meta, str(meta.get("system_prompt") or ""))
    saved = parse_skill_metadata(target, include_prompt=True)
    return saved


def _rewrite_skill(skill_path: Path, meta: dict[str, Any]) -> dict[str, Any]:
    current = parse_skill_metadata(skill_path, include_prompt=True)
    current.update(meta)
    _write_skill(skill_path, current, str(current.get("system_prompt") or ""))
    return parse_skill_metadata(skill_path, include_prompt=True)


def register_skill_success(skills_dir: Path, skill_path: str) -> dict[str, Any]:
    path = Path(skill_path)
    meta = parse_skill_metadata(path, include_prompt=True)
    meta["promotion_success_count"] = _parse_int(
        meta.get("promotion_success_count"), 0
    ) + 1
    updated = _rewrite_skill(path, meta)

    threshold = _parse_int(updated.get("promotion_threshold"), DEFAULT_PROMOTION_THRESHOLD)
    if updated.get("skill_status") == SKILL_STATUS_CANDIDATE and updated["promotion_success_count"] >= threshold:
        family_id = str(updated.get("family_id") or "").strip()
        for existing in list_skills(skills_dir, include_prompt=True):
            if str(existing.get("family_id") or "") != family_id:
                continue
            if existing["path"] == updated["path"]:
                continue
            if existing.get("skill_status") == SKILL_STATUS_ACTIVE:
                _rewrite_skill(Path(existing["path"]), {"skill_status": SKILL_STATUS_ARCHIVED})
        updated = _rewrite_skill(path, {"skill_status": SKILL_STATUS_ACTIVE})
    return updated
