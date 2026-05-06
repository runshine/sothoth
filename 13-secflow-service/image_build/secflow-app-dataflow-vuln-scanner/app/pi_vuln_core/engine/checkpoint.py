"""Step-level workflow checkpoints.

These files are intentionally simple JSON artifacts under ``_meta/checkpoints``.
They make abnormal exits resumable at phase/step granularity without coupling the
agent runtime to workflow-specific concepts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.pi_vuln_core.utils.file_ops import read_json, write_json


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _checkpoint_dir(work_dir: str | Path) -> Path:
    path = Path(work_dir) / "_meta" / "checkpoints"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_step_filename(step_key: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in step_key)
    text = "_".join(part for part in text.split("_") if part)
    return (text[:120] or "step") + ".json"


def record_step_checkpoint(
    work_dir: str | Path,
    *,
    cycle: int,
    phase: str,
    step_key: str,
    status: str,
    agent_id: str = "",
    session_id: str = "",
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist the latest state of a workflow step.

    ``status`` is typically ``started`` / ``completed`` / ``failed``.  The
    current step file is deliberately overwritten so resume can find the latest
    known point in O(1), while per-step history is kept in ``steps/``.
    """
    payload: dict[str, Any] = {
        "timestamp": _now_iso(),
        "cycle": cycle,
        "phase": phase,
        "step_key": step_key,
        "status": status,
        "agent_id": agent_id,
        "session_id": session_id,
        "detail": detail,
    }
    if extra:
        payload["extra"] = extra

    base = _checkpoint_dir(work_dir)
    write_json(base / "current_step.json", payload)

    steps_dir = base / "steps" / f"cycle_{cycle:03d}" / phase
    steps_dir.mkdir(parents=True, exist_ok=True)
    write_json(steps_dir / _safe_step_filename(step_key), payload)
    return payload


def load_current_checkpoint(work_dir: str | Path) -> dict[str, Any] | None:
    path = Path(work_dir) / "_meta" / "checkpoints" / "current_step.json"
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None
