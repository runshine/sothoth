"""Common API dependencies."""

from typing import Optional

from fastapi import Header

from app.config import get_config
from app.exception import ForbiddenError, InternalError, UnauthorizedError
from app.services.auth import (
    AuthServiceError,
    TokenInvalidError,
    get_auth_service,
)
from app.services.project import get_project_service


async def get_current_subject(
    authorization: Optional[str] = Header(None),
) -> tuple[dict, str]:
    if not get_config().auth_service.enabled:
        return (
            {
                "id": "anonymous",
                "username": "anonymous",
                "token_type": "user",
            },
            "",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("缺少 Authorization 头")

    token = authorization.replace("Bearer ", "", 1).strip()
    if not token:
        raise UnauthorizedError("Token 为空")

    try:
        subject = await get_auth_service().validate_token_async(token)
    except TokenInvalidError as exc:
        raise UnauthorizedError(str(exc)) from exc
    except AuthServiceError as exc:
        raise InternalError(str(exc)) from exc

    return subject, token


async def ensure_project_access(project_id: str, token: str) -> dict:
    config = get_config()
    if not config.auth_service.enabled or not config.project_service.enabled:
        return {"id": project_id}

    ok, project = await get_project_service().validate_project_access(token, project_id)
    if not ok:
        raise ForbiddenError(f"无权访问项目: {project_id}")
    return project or {}
