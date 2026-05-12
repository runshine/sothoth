from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from app.models.contracts import TaskItem, TaskManifest


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def abs_path(path: str | Path) -> str:
    return str(Path(path).resolve())


def sanitize_name(value: str) -> str:
    """Return a safe single path component.

    Keep historical support for dots inside names, but never return ``.`` or
    ``..`` (or a value made only of separators).  Callers use this for project
    ids, run names and task ids before appending to filesystem roots, so the
    result must not be able to collapse or climb directories.
    """
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "")).strip("-.")
    if cleaned in {"", ".", ".."}:
        return "item"
    return cleaned


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _atomic_write_text(path: Path, content: str) -> Path:
    ensure_dir(path.parent)
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return path


def write_json(path: str | Path, payload: Any) -> Path:
    target = Path(path)
    return _atomic_write_text(target, json.dumps(payload, ensure_ascii=False, indent=2))


def write_text(path: str | Path, content: str) -> Path:
    target = Path(path)
    ensure_dir(target.parent)
    target.write_text(content, encoding="utf-8")
    return target


def load_task_manifest(path: str | Path) -> TaskManifest:
    return TaskManifest.model_validate(read_json(path))


def write_task_manifest(path: str | Path, tasks: list[TaskItem]) -> Path:
    manifest = TaskManifest(tasks=tasks)
    return write_json(path, manifest.model_dump(mode="json"))
