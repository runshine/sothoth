"""Security helpers."""

from __future__ import annotations

import re

from app.exception import ValidationError


PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_project_id(project_id: str) -> str:
    value = str(project_id or "").strip()
    if not value or not PROJECT_ID_PATTERN.match(value):
        raise ValidationError("project_id 不合法")
    return value
