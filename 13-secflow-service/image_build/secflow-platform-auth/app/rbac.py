"""Platform RBAC helpers."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.model import Role, User

SUPER_ADMIN_ROLE = "super_admin"
ORDINARY_ADMIN_ROLE = "ordinary_admin"
ORDINARY_USER_ROLE = "ordinary_user"

PLATFORM_ROLE_PRIORITY = {
    SUPER_ADMIN_ROLE: 3,
    ORDINARY_ADMIN_ROLE: 2,
    ORDINARY_USER_ROLE: 1,
}

PLATFORM_ROLE_DEFINITIONS: Dict[str, str] = {
    SUPER_ADMIN_ROLE: "超级管理员：拥有用户权限中心与组织架构管理的完整控制权。",
    ORDINARY_ADMIN_ROLE: "普通管理员：仅可在所属部门及下级部门范围内调整用户所属部门。",
    ORDINARY_USER_ROLE: "普通用户：不具备用户权限中心访问权限。",
}

ROLE_ALIASES = {
    "super_admin": SUPER_ADMIN_ROLE,
    "超级管理员": SUPER_ADMIN_ROLE,
    "admin": SUPER_ADMIN_ROLE,
    "管理员": SUPER_ADMIN_ROLE,
    "ordinary_admin": ORDINARY_ADMIN_ROLE,
    "普通管理员": ORDINARY_ADMIN_ROLE,
    "ordinary_user": ORDINARY_USER_ROLE,
    "普通用户": ORDINARY_USER_ROLE,
    "user": ORDINARY_USER_ROLE,
}

ASSIGNABLE_PLATFORM_ROLES = {ORDINARY_ADMIN_ROLE, ORDINARY_USER_ROLE}


def normalize_role_name(role_name: Optional[str]) -> Optional[str]:
    """Normalize raw role names to the platform role namespace."""
    if not role_name:
        return None
    return ROLE_ALIASES.get(role_name.strip().lower(), ROLE_ALIASES.get(role_name.strip()))


def get_platform_role_names(user: User) -> List[str]:
    """Return normalized platform roles attached to a user."""
    roles = {
        normalized
        for role in getattr(user, "roles", []) or []
        for normalized in [normalize_role_name(role.name)]
        if normalized in PLATFORM_ROLE_PRIORITY
    }
    return sorted(roles, key=lambda name: PLATFORM_ROLE_PRIORITY[name], reverse=True)


def get_primary_platform_role(user: User) -> str:
    """Return the highest-priority platform role for a user."""
    role_names = get_platform_role_names(user)
    if role_names:
        return role_names[0]
    return ORDINARY_USER_ROLE


def is_super_admin(user: User) -> bool:
    return get_primary_platform_role(user) == SUPER_ADMIN_ROLE or int(getattr(user, "id", 0) or 0) == 1


def is_ordinary_admin(user: User) -> bool:
    return get_primary_platform_role(user) == ORDINARY_ADMIN_ROLE


def can_access_user_management(user: User) -> bool:
    return is_super_admin(user) or is_ordinary_admin(user)


def ensure_user_management_access(user: User):
    if not can_access_user_management(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="当前用户无权访问用户权限中心"
        )


def ensure_super_admin(user: User):
    if not is_super_admin(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有超级管理员可以执行此操作"
        )


def ensure_platform_roles_seeded(db: Session):
    """Ensure the fixed platform role records exist."""
    created = False
    for role_name, description in PLATFORM_ROLE_DEFINITIONS.items():
        existing = db.query(Role).filter(Role.name == role_name).first()
        if existing:
            if not existing.description:
                existing.description = description
                created = True
            continue
        db.add(Role(name=role_name, description=description))
        created = True

    if created:
        db.commit()


def get_or_create_platform_role(db: Session, role_name: str) -> Role:
    """Fetch a fixed platform role, creating it if needed."""
    normalized = normalize_role_name(role_name)
    if normalized not in PLATFORM_ROLE_DEFINITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的平台角色"
        )

    ensure_platform_roles_seeded(db)
    role = db.query(Role).filter(Role.name == normalized).first()
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="平台角色初始化失败"
        )
    return role


def attach_default_platform_role(db: Session, user: User):
    """Guarantee that a user has the default ordinary-user platform role."""
    if any(normalize_role_name(role.name) in PLATFORM_ROLE_PRIORITY for role in user.roles):
        return

    ordinary_user_role = get_or_create_platform_role(db, ORDINARY_USER_ROLE)
    user.roles = list(user.roles) + [ordinary_user_role]


def set_user_platform_role(db: Session, user: User, role_name: str):
    """Replace only the platform-role slice on a user, preserving custom roles."""
    normalized = normalize_role_name(role_name)
    if normalized not in ASSIGNABLE_PLATFORM_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="只允许分配普通管理员或普通用户角色"
        )

    platform_role = get_or_create_platform_role(db, normalized)
    preserved_roles = [
        role for role in list(user.roles)
        if normalize_role_name(role.name) not in PLATFORM_ROLE_PRIORITY
    ]

    next_roles = preserved_roles + [platform_role]
    deduped = []
    seen_ids = set()
    for role in next_roles:
        if role.id in seen_ids:
            continue
        seen_ids.add(role.id)
        deduped.append(role)

    user.roles = deduped


def filter_non_platform_roles(roles: Iterable[Role]) -> List[Role]:
    return [role for role in roles if normalize_role_name(role.name) not in PLATFORM_ROLE_PRIORITY]
