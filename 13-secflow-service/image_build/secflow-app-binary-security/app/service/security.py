"""Project/path isolation helpers for Binary Security."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.config import get_config
from app.exception import ValidationError


PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def validate_project_id(project_id: str) -> str:
    if not PROJECT_ID_RE.fullmatch(project_id or ""):
        raise ValidationError("project_id 格式不合法")
    return project_id


def validate_task_id(task_id: str) -> str:
    if not TASK_ID_RE.fullmatch(task_id or ""):
        raise ValidationError("task_id 格式不合法")
    return task_id


def project_root(project_id: str) -> Path:
    validate_project_id(project_id)
    return Path(get_config().storage.project_root_template.format(project_id=project_id)).resolve()


def ensure_path_in_project(project_id: str, path: str, *, must_be_file: bool = False) -> Path:
    root = project_root(project_id)
    candidate = Path(path)
    resolved = candidate.resolve() if candidate.is_absolute() else root.joinpath(path.lstrip("/")).resolve()
    if not resolved.is_relative_to(root):
        raise ValidationError(f"路径不在当前项目目录内: {path}")
    if must_be_file and get_config().storage.require_input_exists and not resolved.is_file():
        raise ValidationError(f"输入文件不存在: {path}")
    return resolved


def app_task_root(project_id: str, task_id: str) -> Path:
    validate_project_id(project_id)
    validate_task_id(task_id)
    root = project_root(project_id)
    out = root.joinpath(*_clean_relative(get_config().storage.app_root_name).split("/"), task_id).resolve()
    if not out.is_relative_to(root):
        raise ValidationError("任务工作目录不合法")
    os.makedirs(out, exist_ok=True)
    return out


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _clean_relative(value: str) -> str:
    value = (value or "").strip().replace("\\", "/")
    parts = [part for part in value.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        raise ValidationError("路径不能包含 ..")
    return "/".join(parts)
