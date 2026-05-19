"""Step-level workflow checkpoints.

These files are intentionally simple JSON artifacts under ``_meta/checkpoints``.
They make abnormal exits resumable at phase/step granularity without coupling the
agent runtime to workflow-specific concepts.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import time
from typing import Any

from app.pi_vuln_core.utils.file_ops import read_json, write_json
from app.time_utils import isoformat_local, now_local

RESUME_TERMINAL_STATUSES = frozenset({"completed", "partial_salvaged", "soft_failed"})
TIMING_FINISHED_STATUSES = RESUME_TERMINAL_STATUSES | frozenset({"failed", "error", "cancelled", "interrupted"})


def _now_iso() -> str:
    return isoformat_local(now_local()) or ""


def _checkpoint_dir(work_dir: str | Path) -> Path:
    path = Path(work_dir) / "_meta" / "checkpoints"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_step_filename(step_key: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in step_key)
    text = "_".join(part for part in text.split("_") if part)
    return (text[:120] or "step") + ".json"


def _safe_epoch(value: Any) -> float:
    try:
        epoch = float(value)
    except (TypeError, ValueError):
        return 0.0
    return epoch if epoch > 0 else 0.0


def normalize_step_key(phase: str, step_key: str) -> str:
    """Return the stable persisted key for a workflow node."""
    phase = (phase or "").strip()
    step_key = (step_key or "").strip()
    if phase == "worker" and not step_key:
        return "worker::work"
    if phase == "summary" and not step_key:
        return "summary"
    return step_key


def node_id_for(*, cycle: int, phase: str, step_key: str) -> str:
    """Return a stable identifier for a resumable workflow node.

    A node is one business-level interaction with piagent.  The ID is stable
    across process restarts so frontend traces and resume previews can point to
    the same node even when the underlying runtime call directory changes.
    """
    normalized_phase = (phase or "").strip()
    normalized_step = normalize_step_key(normalized_phase, step_key)
    raw = f"cycle={int(cycle):03d}|phase={normalized_phase}|step={normalized_step}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]


def node_kind_for(phase: str, step_key: str) -> str:
    phase = (phase or "").strip()
    step_key = (step_key or "").strip()
    if phase == "worker":
        if step_key == "worker::rework_triage":
            return "worker_rework_triage"
        if step_key == "worker::rework_fp_repair":
            return "worker_rework_false_positive_repair"
        if step_key == "worker::rework_missed_hunt":
            return "worker_rework_missed_vuln_hunting"
        if step_key == "worker::rework_handoff":
            return "worker_rework_closure_handoff"
        if step_key == "worker::rework":
            return "worker_rework"
        return "worker_work"
    if phase == "reflect":
        return "reflection"
    if phase == "summary":
        return "summary"
    if phase == "global_review" or step_key.startswith("global::"):
        return "global_review"
    if phase == "result_review" or step_key.startswith("result::"):
        return "result_review"
    return "unknown"


def is_terminal_checkpoint(checkpoint: dict[str, Any] | None) -> bool:
    if not isinstance(checkpoint, dict):
        return False
    return str(checkpoint.get("status") or "").strip() in RESUME_TERMINAL_STATUSES


def _worker_step_aliases(step_key: str) -> list[str]:
    staged_rework = {
        "worker::rework_triage",
        "worker::rework_missed_hunt",
        "worker::rework_handoff",
    }
    if step_key in staged_rework:
        return [step_key]
    if step_key in {"worker::work", "worker::rework"}:
        # Old runs persisted both initial work and rework as plain "worker".
        return [step_key, "worker"]
    if step_key == "worker":
        return ["worker", "worker::work", "worker::rework"]
    return [step_key]


def load_step_checkpoint(
    work_dir: str | Path,
    *,
    cycle: int,
    phase: str,
    step_key: str,
) -> dict[str, Any] | None:
    """Load a specific step checkpoint, including legacy worker aliases."""
    phase = (phase or "").strip()
    step_key = normalize_step_key(phase, step_key)
    steps_dir = (
        Path(work_dir)
        / "_meta"
        / "checkpoints"
        / "steps"
        / f"cycle_{int(cycle):03d}"
        / phase
    )
    if not steps_dir.is_dir():
        return None

    aliases = _worker_step_aliases(step_key) if phase == "worker" else [step_key]
    for candidate in aliases:
        path = steps_dir / _safe_step_filename(candidate)
        if not path.is_file():
            continue
        try:
            payload = read_json(path)
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def load_step_checkpoints(
    work_dir: str | Path,
    *,
    cycle: int | None = None,
) -> list[dict[str, Any]]:
    """Return persisted step checkpoints, sorted by cycle and mtime."""
    root = Path(work_dir) / "_meta" / "checkpoints" / "steps"
    if not root.is_dir():
        return []

    records: list[tuple[int, float, dict[str, Any]]] = []
    cycle_dirs = [root / f"cycle_{int(cycle):03d}"] if cycle is not None else sorted(root.glob("cycle_*"))
    for cycle_dir in cycle_dirs:
        if not cycle_dir.is_dir():
            continue
        for path in sorted(cycle_dir.glob("*/*.json")):
            try:
                payload = read_json(path)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            try:
                item_cycle = int(payload.get("cycle") or 0)
            except (TypeError, ValueError):
                item_cycle = 0
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = 0.0
            records.append((item_cycle, mtime, payload))
    records.sort(key=lambda item: (item[0], item[1]))
    return [payload for _, _, payload in records]


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
    step_key = normalize_step_key(phase, step_key)
    node_kind = node_kind_for(phase, step_key)
    node_id = node_id_for(cycle=cycle, phase=phase, step_key=step_key)
    now_iso = _now_iso()
    now_epoch = time.time()
    base = _checkpoint_dir(work_dir)
    steps_dir = base / "steps" / f"cycle_{cycle:03d}" / phase
    existing_path = steps_dir / _safe_step_filename(step_key)
    existing = {}
    if existing_path.is_file():
        try:
            loaded = read_json(existing_path)
            existing = loaded if isinstance(loaded, dict) else {}
        except Exception:
            existing = {}

    payload: dict[str, Any] = {
        "schema_version": 1,
        "timestamp": now_iso,
        "cycle": cycle,
        "phase": phase,
        "step_key": step_key,
        "node_id": node_id,
        "status": status,
        "node_kind": node_kind,
        "terminal_status": status in RESUME_TERMINAL_STATUSES,
        "resume_policy": "rerun_current_node",
        "agent_id": agent_id,
        "session_id": session_id,
        "detail": detail,
    }

    if status == "started":
        payload["started_at"] = now_iso
        payload["started_epoch"] = now_epoch
    elif status in TIMING_FINISHED_STATUSES:
        started_at = str(existing.get("started_at") or "").strip()
        started_epoch = _safe_epoch(existing.get("started_epoch"))
        if started_at:
            payload["started_at"] = started_at
        if started_epoch > 0:
            payload["started_epoch"] = started_epoch
        payload["finished_at"] = now_iso
        payload["finished_epoch"] = now_epoch
        if started_epoch > 0:
            duration_ms = max(int(round((now_epoch - started_epoch) * 1000)), 0)
            payload["duration_ms"] = duration_ms
            payload["duration_seconds"] = max(int(round(duration_ms / 1000)), 0)

    if extra:
        payload["extra"] = extra

    write_json(base / "current_step.json", payload)

    steps_dir.mkdir(parents=True, exist_ok=True)
    write_json(existing_path, payload)
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
