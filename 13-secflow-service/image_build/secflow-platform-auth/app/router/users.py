"""用户路由"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import cleanup_expired_sessions, get_password_hash, verify_password
from app.database import get_db
from app.dependencies import get_current_super_admin, get_current_user
from app.model import Department, DepartmentMember, Role, User, UserSession
from app.rbac import (
    PLATFORM_ROLE_PRIORITY,
    attach_default_platform_role,
    ensure_platform_roles_seeded,
    filter_non_platform_roles,
    get_platform_role_names,
    get_primary_platform_role,
    normalize_role_name,
    set_user_platform_role,
)
from app.schema import (
    ChangeOwnPasswordRequest,
    ChangePasswordRequest,
    Message,
    OnlineUserResponse,
    PlatformRoleResponse,
    PlatformRoleUpdateRequest,
    UserCreate,
    UserDetailResponse,
    UserResponse,
    UserRoleBindRequest,
    UserRoleResponse,
    UserUpdate,
)

router = APIRouter(tags=["用户管理"], prefix="/users")


def _get_primary_department_membership(db: Session, user_id: int) -> Optional[DepartmentMember]:
    return db.query(DepartmentMember).filter(
        DepartmentMember.user_id == user_id
    ).order_by(DepartmentMember.id.asc()).first()


def _build_user_response(db: Session, user: User) -> UserResponse:
    membership = _get_primary_department_membership(db, user.id)
    department = None
    if membership:
        department = db.query(Department).filter(Department.id == membership.department_id).first()

    return UserResponse(
        id=user.id,
        username=user.username,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
        role=user.get_all_role_names(),
        platform_role=get_primary_platform_role(user),
        department_member_id=membership.id if membership else None,
        department_id=membership.department_id if membership else None,
        department_name=department.name if department else None,
    )


def _validate_role_ids_exist(db: Session, role_ids: List[int]) -> List[Role]:
    roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
    if len(roles) != len(role_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="部分角色不存在"
        )
    return roles


@router.get("/user_list", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """获取用户列表。仅超级管理员可访问。"""
    ensure_platform_roles_seeded(db)
    users = db.query(User).order_by(User.id.asc()).all()
    return [_build_user_response(db, user) for user in users]


@router.get("/{user_id}", response_model=UserDetailResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """获取单个用户。仅超级管理员可访问。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    response = _build_user_response(db, user)
    return UserDetailResponse(
        **response.model_dump(),
        role_ids=[role.id for role in user.roles]
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """创建用户。新用户默认附带普通用户角色。"""
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已存在"
        )

    ensure_platform_roles_seeded(db)

    user = User(
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password)
    )
    db.add(user)
    db.flush()

    extra_roles: List[Role] = []
    if user_data.role_ids:
        roles = _validate_role_ids_exist(db, user_data.role_ids)
        extra_roles = filter_non_platform_roles(roles)

    user.roles = list(extra_roles)
    attach_default_platform_role(db, user)

    db.commit()
    db.refresh(user)
    return _build_user_response(db, user)


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """更新用户基础信息。仅超级管理员可访问。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    if user_data.username:
        existing = db.query(User).filter(
            User.username == user_data.username,
            User.id != user_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="用户名已存在"
            )
        user.username = user_data.username

    if user_data.password:
        user.hashed_password = get_password_hash(user_data.password)

    if user_data.is_active is not None:
        user.is_active = user_data.is_active

    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return _build_user_response(db, user)


@router.delete("/{user_id}", response_model=Message)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """删除用户。仅超级管理员可访问。"""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除当前登录的超级管理员"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    db.delete(user)
    db.commit()

    return {"message": "用户已删除"}


@router.get("/{user_id}/role", response_model=UserRoleResponse)
def get_user_roles(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """获取用户的原始角色列表。仅超级管理员可访问。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.roles],
        role_names=[role.name for role in user.roles]
    )


@router.put("/{user_id}/role", response_model=UserRoleResponse)
def bind_user_role(
    user_id: int,
    role_data: UserRoleBindRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """覆盖用户角色。保留接口兼容性，仅超级管理员可访问。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    roles = _validate_role_ids_exist(db, role_data.role_ids)
    normalized_role_names = {
        normalize_role_name(role.name)
        for role in roles
    }
    if "super_admin" in normalized_role_names:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="超级管理员角色为保留角色，不能通过该接口直接分配"
        )

    user.roles = roles
    attach_default_platform_role(db, user)
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.roles],
        role_names=[role.name for role in user.roles]
    )


@router.post("/{user_id}/role/add", response_model=UserRoleResponse)
def add_user_role(
    user_id: int,
    role_data: UserRoleBindRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """增量添加角色。仅超级管理员可访问。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    roles = _validate_role_ids_exist(db, role_data.role_ids)
    if any(normalize_role_name(role.name) == "super_admin" for role in roles):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="超级管理员角色为保留角色，不能通过该接口直接分配"
        )

    all_roles = list(user.roles)
    known_ids = {role.id for role in all_roles}
    for role in roles:
        if role.id not in known_ids:
            known_ids.add(role.id)
            all_roles.append(role)

    user.roles = all_roles
    attach_default_platform_role(db, user)
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.roles],
        role_names=[role.name for role in user.roles]
    )


@router.delete("/{user_id}/role", response_model=UserRoleResponse)
def remove_user_role(
    user_id: int,
    role_data: UserRoleBindRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """移除角色。至少保留一个平台角色。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    user.roles = [role for role in user.roles if role.id not in set(role_data.role_ids)]
    attach_default_platform_role(db, user)
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.roles],
        role_names=[role.name for role in user.roles]
    )


@router.get("/{user_id}/platform-role", response_model=PlatformRoleResponse)
def get_user_platform_role(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """获取用户的平台角色。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    return PlatformRoleResponse(
        user_id=user.id,
        platform_role=get_primary_platform_role(user),
        role_names=user.get_all_role_names()
    )


@router.put("/{user_id}/platform-role", response_model=PlatformRoleResponse)
def update_user_platform_role(
    user_id: int,
    request: PlatformRoleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """仅允许超级管理员在普通管理员与普通用户之间切换。"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    if user.id == current_user.id or user.id == 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="当前超级管理员账号的角色不允许在此页面中修改"
        )

    set_user_platform_role(db, user, request.role_name)
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)

    return PlatformRoleResponse(
        user_id=user.id,
        platform_role=get_primary_platform_role(user),
        role_names=user.get_all_role_names()
    )


@router.post("/{user_id}/password", response_model=Message)
def change_password(
    user_id: int,
    request: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    超级管理员修改指定用户的密码。

    old_password 用于校验当前超级管理员自己的密码，避免高权限操作被误用。
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    if not verify_password(request.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="超级管理员密码验证失败"
        )

    if not request.new_password or len(request.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能为空且长度至少6位"
        )

    user.hashed_password = get_password_hash(request.new_password)
    user.updated_at = datetime.utcnow()

    db.commit()

    return {"message": "密码已修改"}


@router.post("/password/self", response_model=Message)
def change_own_password(
    request: ChangeOwnPasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    当前登录用户修改自己的密码。
    """
    if not verify_password(request.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码错误"
        )

    if not request.new_password or len(request.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能为空且长度至少6位"
        )

    current_user.hashed_password = get_password_hash(request.new_password)
    current_user.updated_at = datetime.utcnow()

    db.commit()

    return {"message": "密码已修改"}


@router.get("/sessions/online", response_model=List[OnlineUserResponse])
def get_online_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    获取当前在线用户列表。仅超级管理员可访问。
    """
    cleanup_expired_sessions(db)

    now = datetime.utcnow()
    active_sessions = db.query(UserSession).filter(
        UserSession.status == "active",
        UserSession.expires_at > now
    ).order_by(UserSession.last_active_at.desc()).all()

    online_users = []
    seen_user_ids = set()

    for session in active_sessions:
        if session.user_id in seen_user_ids:
            continue
        seen_user_ids.add(session.user_id)

        user = session.user
        online_users.append(OnlineUserResponse(
            user_id=user.id,
            username=user.username,
            role=user.get_all_role_names(),
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            login_at=session.created_at,
            last_active_at=session.last_active_at
        ))

    return online_users


@router.get("/{user_id}/sessions", response_model=List[dict])
def get_user_sessions(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    获取指定用户的所有会话。仅超级管理员可访问。
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    cleanup_expired_sessions(db)

    sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id
    ).order_by(UserSession.created_at.desc()).all()

    return [
        {
            "id": s.id,
            "token_jti": s.token_jti,
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "status": s.status,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "last_active_at": s.last_active_at.isoformat() if s.last_active_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None
        }
        for s in sessions
    ]


@router.delete("/{user_id}/sessions", response_model=Message)
def revoke_user_sessions(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    撤销指定用户的所有会话（踢下线）。仅超级管理员可访问。
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.status == "active"
    ).all()

    for session in active_sessions:
        session.status = "revoked"

    db.commit()

    return {"message": f"已撤销用户 {user.username} 的所有会话"}
