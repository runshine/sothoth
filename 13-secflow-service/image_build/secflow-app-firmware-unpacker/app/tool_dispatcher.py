"""Deterministic magic-based tool dispatcher and versioned tool repository helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from app.tool_store import parse_tool_metadata


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return slug.strip("-") or "generic-tool"


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def ensure_dispatcher_environment(
    *,
    tools_root_dir: Path,
    tools_store_dir: Path,
    tools_active_dir: Path,
    dispatcher_dir: Path,
    dispatcher_rules_path: Path,
) -> None:
    tools_root_dir.mkdir(parents=True, exist_ok=True)
    tools_store_dir.mkdir(parents=True, exist_ok=True)
    tools_active_dir.mkdir(parents=True, exist_ok=True)
    dispatcher_dir.mkdir(parents=True, exist_ok=True)
    if not dispatcher_rules_path.exists():
        dispatcher_rules_path.write_text(
            json.dumps({"version": 1, "rules": []}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def load_dispatcher_rules(dispatcher_rules_path: Path) -> dict[str, Any]:
    if not dispatcher_rules_path.exists():
        return {"version": 1, "rules": []}
    try:
        payload = json.loads(dispatcher_rules_path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "rules": []}
    if not isinstance(payload, dict):
        return {"version": 1, "rules": []}
    rules = payload.get("rules")
    if not isinstance(rules, list):
        payload["rules"] = []
    return payload


def save_dispatcher_rules(dispatcher_rules_path: Path, payload: dict[str, Any]) -> None:
    dispatcher_rules_path.parent.mkdir(parents=True, exist_ok=True)
    dispatcher_rules_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def family_store_dir(tools_store_dir: Path, family_id: str) -> Path:
    path = tools_store_dir / ".families" / _slugify(family_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def family_manifest_path(tools_store_dir: Path, family_id: str) -> Path:
    return family_store_dir(tools_store_dir, family_id) / "manifest.json"


def read_family_manifest(tools_store_dir: Path, family_id: str) -> dict[str, Any]:
    path = family_manifest_path(tools_store_dir, family_id)
    if not path.exists():
        return {
            "family_id": _slugify(family_id),
            "magic_hex": "",
            "current_version": None,
            "versions": [],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("family_id", _slugify(family_id))
    payload.setdefault("magic_hex", "")
    payload.setdefault("current_version", None)
    payload.setdefault("versions", [])
    return payload


def write_family_manifest(tools_store_dir: Path, family_id: str, payload: dict[str, Any]) -> None:
    path = family_manifest_path(tools_store_dir, family_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_tool_version(path: Path) -> int | None:
    name = path.name
    match = re.match(r"^v(\d+)__", name)
    if match:
        return int(match.group(1))
    match = re.search(r"-v(\d+)-\d{14}\.py$", name)
    if match:
        return int(match.group(1))
    return None


def next_tool_version(tools_store_dir: Path, family_id: str) -> int:
    family_slug = _slugify(family_id)
    version_max = 0
    for tool_path in tools_store_dir.glob("*/*.py"):
        if not tool_path.is_file():
            continue
        if tool_path.parent.name.startswith("."):
            continue
        if not tool_path.name.startswith(f"{family_slug}-v"):
            continue
        version = parse_tool_version(tool_path)
        if version is not None:
            version_max = max(version_max, version)
    return version_max + 1


def build_versioned_tool_path(tools_store_dir: Path, family_id: str, version: int, timestamp: str) -> Path:
    day_dir = tools_store_dir / str(timestamp or "")[:8]
    day_dir.mkdir(parents=True, exist_ok=True)
    return day_dir / f"{_slugify(family_id)}-v{int(version)}-{timestamp}.py"


def active_tool_path(tools_active_dir: Path, family_id: str) -> Path:
    tools_active_dir.mkdir(parents=True, exist_ok=True)
    return tools_active_dir / f"{_slugify(family_id)}.py"


def resolve_active_tool_target(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except Exception:
        return path


def _replace_with_symlink(link_path: Path, target_path: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)
    if link_path.exists() or link_path.is_symlink():
        _safe_unlink(link_path)
    try:
        relative_target = os.path.relpath(target_path, start=link_path.parent)
        link_path.symlink_to(relative_target)
    except Exception:
        shutil.copy2(target_path, link_path)


def activate_tool_version(
    *,
    tools_store_dir: Path,
    tools_active_dir: Path,
    family_id: str,
    target_path: Path,
    magic_hex: str = "",
    source: str = "manual",
) -> Path:
    family_id = _slugify(family_id)
    manifest = read_family_manifest(tools_store_dir, family_id)
    target_path = target_path.resolve()
    try:
        target_path.relative_to(tools_store_dir.resolve())
    except Exception as exc:
        raise ValueError(f"target_path must be inside tools store: {target_path}") from exc
    try:
        version_name = str(target_path.relative_to(tools_store_dir))
    except Exception:
        version_name = target_path.name
    versions = list(manifest.get("versions") or [])
    for item in versions:
        if str(item.get("file") or "") == version_name:
            item["status"] = "active"
        elif str(item.get("status") or "") == "active":
            item["status"] = "archived"
    if not any(str(item.get("file") or "") == version_name for item in versions):
        versions.append(
            {
                "file": version_name,
                "created_at": __import__("datetime").datetime.now().astimezone().isoformat(),
                "source": source,
                "status": "active",
            }
        )
    manifest["family_id"] = family_id
    if magic_hex:
        manifest["magic_hex"] = str(magic_hex).strip().lower()
    manifest["current_version"] = version_name
    manifest["versions"] = versions
    write_family_manifest(tools_store_dir, family_id, manifest)
    active_path = active_tool_path(tools_active_dir, family_id)
    _replace_with_symlink(active_path, target_path)
    return active_path


def upsert_dispatcher_rule(
    *,
    dispatcher_rules_path: Path,
    family_id: str,
    magic_hex: str,
    tool_path: Path,
    description: str = "",
) -> dict[str, Any]:
    family_id = _slugify(family_id)
    magic_hex = str(magic_hex or "").strip().lower()
    payload = load_dispatcher_rules(dispatcher_rules_path)
    rules = list(payload.get("rules") or [])
    rule_id = family_id
    updated = False
    for item in rules:
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or "") == rule_id or str(item.get("magic_hex") or "").strip().lower() == magic_hex:
            item["id"] = rule_id
            item["enabled"] = True
            item["magic_hex"] = magic_hex
            item["family_id"] = family_id
            item["tool"] = str(tool_path)
            item["description"] = description or str(item.get("description") or "")
            updated = True
            break
    if not updated:
        rules.append(
            {
                "id": rule_id,
                "enabled": True,
                "magic_hex": magic_hex,
                "family_id": family_id,
                "tool": str(tool_path),
                "description": description,
            }
        )
    payload["version"] = 1
    payload["rules"] = rules
    save_dispatcher_rules(dispatcher_rules_path, payload)
    return next((item for item in rules if isinstance(item, dict) and str(item.get("id") or "") == rule_id), {})


def find_dispatcher_rule(
    *,
    dispatcher_rules_path: Path,
    family_id: str,
    magic_hex: str = "",
) -> dict[str, Any] | None:
    family_id = _slugify(family_id)
    magic_hex = str(magic_hex or "").strip().lower()
    payload = load_dispatcher_rules(dispatcher_rules_path)
    for item in payload.get("rules") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or "") == family_id:
            return item
        if magic_hex and str(item.get("magic_hex") or "").strip().lower() == magic_hex:
            return item
    return None


def dispatch_tool_by_magic(features: dict[str, Any], dispatcher_rules_path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    payload = load_dispatcher_rules(dispatcher_rules_path)
    feat_magic = str(features.get("magic_hex") or "").strip().lower()
    if not feat_magic:
        return None, {"reasons": ["missing_magic_hex"]}
    for item in payload.get("rules") or []:
        if not isinstance(item, dict):
            continue
        if not bool(item.get("enabled", True)):
            continue
        rule_magic = str(item.get("magic_hex") or "").strip().lower()
        if not rule_magic or rule_magic != feat_magic:
            continue
        tool_path = Path(str(item.get("tool") or "").strip())
        if not tool_path.is_file():
            return None, {
                "reasons": [f"matched_rule:{item.get('id')}", f"tool_not_found:{tool_path}"],
                "dispatch_rule_id": str(item.get("id") or ""),
            }
        meta = parse_tool_metadata(tool_path)
        meta["path"] = str(tool_path)
        meta["family_id"] = str(item.get("family_id") or meta.get("format_id") or meta.get("name") or "")
        meta["dispatch_rule_id"] = str(item.get("id") or "")
        meta["magic_hex"] = rule_magic or str(meta.get("magic_hex") or "")
        meta["tool_version"] = parse_tool_version(resolve_active_tool_target(tool_path))
        return meta, {
            "reasons": [f"magic:{rule_magic}"],
            "dispatch_rule_id": str(item.get("id") or ""),
        }
    return None, {"reasons": [f"no_rule_for_magic:{feat_magic}"]}


__all__ = [
    "activate_tool_version",
    "active_tool_path",
    "build_versioned_tool_path",
    "dispatch_tool_by_magic",
    "ensure_dispatcher_environment",
    "family_manifest_path",
    "family_store_dir",
    "find_dispatcher_rule",
    "load_dispatcher_rules",
    "next_tool_version",
    "parse_tool_version",
    "read_family_manifest",
    "resolve_active_tool_target",
    "upsert_dispatcher_rule",
    "write_family_manifest",
]
