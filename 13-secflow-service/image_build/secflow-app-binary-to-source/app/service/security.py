"""Project/path isolation helpers."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.config import get_config
from app.exception import ValidationError

PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def validate_project_id(project_id: str) -> str:
    if not PROJECT_ID_RE.fullmatch(project_id or ""):
        raise ValidationError("project_id格式不合法")
    return project_id


def project_root(project_id: str) -> Path:
    validate_project_id(project_id)
    return Path(get_config().storage.project_root_template.format(project_id=project_id)).resolve()


def ensure_path_in_project(project_id: str, path: str, *, must_be_file: bool = False) -> Path:
    root = project_root(project_id)
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(root):
        raise ValidationError(f"路径不在当前项目目录内: {path}")
    if must_be_file and get_config().storage.require_input_exists and not resolved.is_file():
        raise ValidationError(f"输入文件不存在: {path}")
    return resolved


def safe_output_dir(project_id: str, task_id: str, sequence_no: int, output_subdir: str | None = None) -> Path:
    root = project_root(project_id)
    parts = [get_config().storage.output_root_name, task_id]
    if output_subdir:
        cleaned = _clean_relative(output_subdir)
        if cleaned:
            parts.extend(cleaned.split("/"))
    parts.append(str(sequence_no))
    out = root.joinpath(*parts).resolve()
    if not out.is_relative_to(root):
        raise ValidationError("输出目录不合法")
    os.makedirs(out, exist_ok=True)
    return out


def _clean_relative(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if not value or value == "/":
        return ""
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValidationError("output_subdir不能包含路径穿越")
    return "/".join(parts)
