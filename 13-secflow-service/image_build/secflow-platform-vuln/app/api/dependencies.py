"""Common API dependencies."""

from typing import Optional

from fastapi import Header, HTTPException

from app.services.auth import get_auth_service
from app.services.project import get_project_service


async def get_current_subject(authorization: Optional[str] = Header(None)) -> tuple[dict, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization.replace("Bearer ", "", 1)
    subject = await get_auth_service().validate_token(token)
    if subject is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return subject, token


async def ensure_project_access(project_id: str, token: str) -> dict:
    ok, project = await get_project_service().validate_project_access(project_id, token)
    if not ok:
        raise HTTPException(status_code=403, detail=f"No permission to access project {project_id}")
    return project or {}
