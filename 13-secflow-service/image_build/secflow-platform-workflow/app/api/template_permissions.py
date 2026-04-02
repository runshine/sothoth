"""
Shared template permission helpers.
"""
import logging
from typing import Any, Optional

from app.services import AuthServiceError, get_auth_service

logger = logging.getLogger(__name__)


def _user_roles(current_user: dict) -> set[str]:
    roles = current_user.get("role", []) or []
    return {str(role) for role in roles}


def is_super_admin(current_user: dict) -> bool:
    roles = _user_roles(current_user)
    platform_role = current_user.get("platform_role")
    return platform_role == "super_admin" or "super_admin" in roles or "admin" in roles


def is_ordinary_admin(current_user: dict) -> bool:
    roles = _user_roles(current_user)
    platform_role = current_user.get("platform_role")
    return platform_role == "ordinary_admin" or "ordinary_admin" in roles


async def _get_accessible_projects(current_user: dict) -> list[dict[str, Any]]:
    token = current_user.get("token")
    if not token:
        return []

    try:
        projects = await get_auth_service().get_user_department_projects_async(token)
    except AuthServiceError as exc:
        logger.warning("Failed to query user projects for template permission: %s", exc)
        return []

    return projects if isinstance(projects, list) else []


async def can_access_project(current_user: dict, project_id: Optional[str]) -> bool:
    if not project_id:
        return False
    if is_super_admin(current_user):
        return True

    projects = await _get_accessible_projects(current_user)
    return any(str(project.get("id")) == str(project_id) for project in projects)


async def can_manage_project(current_user: dict, project_id: Optional[str]) -> bool:
    if not project_id:
        return False
    if is_super_admin(current_user):
        return True
    if not is_ordinary_admin(current_user):
        return False

    projects = await _get_accessible_projects(current_user)
    return any(
        str(project.get("id")) == str(project_id) and bool(project.get("can_manage"))
        for project in projects
    )


async def can_modify_template(current_user: dict, template: Any) -> bool:
    user_id = str(current_user.get("id", ""))
    if str(getattr(template, "created_by", "")) == user_id:
        return True
    if is_super_admin(current_user):
        return True
    if getattr(template, "scope", None) == "global":
        return False
    return await can_manage_project(current_user, getattr(template, "project_id", None))


async def can_read_template(current_user: dict, template: Any) -> bool:
    if getattr(template, "scope", None) == "global":
        return True
    if await can_modify_template(current_user, template):
        return True
    return await can_access_project(current_user, getattr(template, "project_id", None))
