from __future__ import annotations

import uuid
from typing import Optional, Tuple

from fastapi import Header, HTTPException, status

from app.models.database import get_db
from app.services.auth import get_auth_service
from app.services.project import ProjectServiceError, get_project_service


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


async def get_current_subject(authorization: Optional[str] = Header(default=None)) -> Tuple[dict, str]:
    auth = get_auth_service()
    return await auth.validate_human_authorization(authorization)


async def get_current_or_machine_subject(authorization: Optional[str] = Header(default=None)) -> Tuple[dict, str]:
    auth = get_auth_service()
    try:
        return await auth.validate_human_authorization(authorization)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            raise
    return await auth.validate_machine_authorization(authorization)


async def get_machine_subject(authorization: Optional[str] = Header(default=None)) -> Tuple[dict, str]:
    auth = get_auth_service()
    return await auth.validate_machine_authorization(authorization)


async def ensure_project_access(project_id: str, token: str | None) -> dict:
    try:
        ok, project = get_project_service().validate_project_access(project_id, token)
    except ProjectServiceError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"project access denied: {project_id}")
    return project or {}


__all__ = [
    "ensure_project_access",
    "generate_id",
    "get_db",
    "get_current_or_machine_subject",
    "get_current_subject",
    "get_machine_subject",
]
