from __future__ import annotations

import json
import re
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
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "item"


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any) -> Path:
    target = Path(path)
    ensure_dir(target.parent)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


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
