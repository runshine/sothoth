"""Session artifact helpers for firmware unpacking agents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.unpacker_engine_config import slug_session_part, utc_now_iso


def get_session_dir(log_dir: Path | None) -> Path | None:
    if log_dir is None:
        return None
    session_dir = log_dir / "sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    index_path = session_dir / "index.json"
    if not index_path.exists():
        index_path.write_text(
            json.dumps({"version": 1, "items": []}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return session_dir


def session_index_path(session_dir: Path | None) -> Path | None:
    if session_dir is None:
        return None
    return session_dir / "index.json"


def load_session_index(session_dir: Path | None) -> dict[str, Any]:
    path = session_index_path(session_dir)
    if path is None or not path.exists():
        return {"version": 1, "items": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "items": []}
    items = payload.get("items")
    if not isinstance(items, list):
        items = []
    return {"version": 1, "items": items}


def write_session_index(session_dir: Path | None, payload: dict[str, Any]) -> None:
    path = session_index_path(session_dir)
    if path is None:
        return
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_session_artifacts(
    log_dir: Path | None,
    *,
    role: str,
    name: str,
    provider_role: str | None,
    phase: str,
    round_id: int | None = None,
    skill_name: str | None = None,
) -> dict[str, Any]:
    session_dir = get_session_dir(log_dir)
    if session_dir is None:
        raise ValueError("session artifacts require a valid log_dir")
    role_slug = slug_session_part(role, fallback="agent")
    name_slug = slug_session_part(name, fallback="default")
    session_file = f"{role_slug}.{name_slug}.session.jsonl"
    session_path = session_dir / session_file
    session_path.touch(exist_ok=True)
    return {
        "session_dir": session_dir,
        "session_path": session_path,
        "session_role": role_slug,
        "session_name": name_slug,
        "provider_role": str(provider_role or "").strip() or None,
        "phase": phase,
        "round": round_id,
        "skill_name": skill_name,
    }


def update_session_index(
    session_dir: Path | None,
    *,
    role: str,
    name: str,
    session_file: str,
    provider_role: str | None,
    phase: str,
    status: str,
    round_id: int | None = None,
    skill_name: str | None = None,
) -> None:
    if session_dir is None:
        return
    payload = load_session_index(session_dir)
    items = payload["items"]
    entry = next(
        (
            item
            for item in items
            if item.get("role") == role and item.get("name") == name
        ),
        None,
    )
    now = utc_now_iso()
    if entry is None:
        entry = {
            "role": role,
            "name": name,
            "session_file": session_file,
            "provider_role": provider_role,
            "status": status,
            "created_at": now,
            "updated_at": now,
            "closed_at": None,
            "round": round_id,
            "skill_name": skill_name,
            "phase": phase,
        }
        items.append(entry)
    else:
        entry["session_file"] = session_file
        entry["provider_role"] = provider_role
        entry["status"] = status
        entry["updated_at"] = now
        entry["round"] = round_id
        entry["skill_name"] = skill_name
        entry["phase"] = phase
    if status in {"closed", "failed"}:
        entry["closed_at"] = now
    else:
        entry["closed_at"] = None
    write_session_index(session_dir, payload)
