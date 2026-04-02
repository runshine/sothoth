"""Common API dependencies."""

from typing import Optional

from fastapi import Header

from app.exception import ForbiddenError, UnauthorizedError
from app.services.auth import get_auth_service
from app.services.project import get_project_service


async def get_current_subject(authorization: Optional[str] = Header(None)) -> tuple[dict, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("缺少 Authorization 头")

    token = authorization.replace("Bearer ", "", 1)
    subject = await get_auth_service().validate_token(token)
    if subject is None:
        raise UnauthorizedError("Token 无效或已过期")
    return subject, token


async def ensure_project_access(project_id: str, token: str) -> dict:
    ok, project = await get_project_service().validate_project_access(token, project_id)
    if not ok:
        raise ForbiddenError(f"无权访问项目: {project_id}")
    return project or {}
