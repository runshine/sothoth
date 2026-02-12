"""用户路由"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.auth import get_password_hash, verify_password, cleanup_expired_sessions
from app.dependencies import get_current_user
from app.schema import (
    UserCreate, UserUpdate, UserResponse, UserDetailResponse,
    UserRoleBindRequest, UserRoleResponse, Message,
    ChangePasswordRequest, ChangeOwnPasswordRequest,
    OnlineUserResponse
)
from app.model import User, Role, UserSession

router = APIRouter(tags=["用户管理"])


@router.get("/user_list", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db)):
    """获取用户列表"""
    users = db.query(User).all()
    return users


@router.get("/{user_id}", response_model=UserDetailResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    """获取单个用户"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )
    return user


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """创建用户"""
    # 检查用户名是否已存在
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已存在"
        )

    # 创建用户
    user = User(
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password)
    )

    # 绑定角色
    if user_data.role_ids:
        roles = db.query(Role).filter(Role.id.in_(user_data.role_ids)).all()
        user.roles = roles

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_data: UserUpdate, db: Session = Depends(get_db)):
    """更新用户"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 更新字段
    if user_data.username:
        # 检查新用户名是否被其他用户使用
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

    return user


@router.delete("/{user_id}", response_model=Message)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """删除用户"""
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
def get_user_roles(user_id: int, db: Session = Depends(get_db)):
    """获取用户的角色"""
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
def bind_user_role(user_id: int, role_data: UserRoleBindRequest, db: Session = Depends(get_db)):
    """绑定用户角色（覆盖模式）"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 验证角色是否存在
    roles = db.query(Role).filter(Role.id.in_(role_data.role_ids)).all()
    if len(roles) != len(role_data.role_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="部分角色不存在"
        )

    # 绑定角色（覆盖已有角色）
    user.role = roles
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.role],
        role_names=[role.name for role in user.role]
    )


@router.post("/{user_id}/role/add", response_model=UserRoleResponse)
def add_user_role(user_id: int, role_data: UserRoleBindRequest, db: Session = Depends(get_db)):
    """添加用户角色（增量模式）"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 验证角色是否存在
    roles = db.query(Role).filter(Role.id.in_(role_data.role_ids)).all()
    existing_role_ids = [r.id for r in roles]

    missing_ids = [rid for rid in role_data.role_ids if rid not in existing_role_ids]
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"角色不存在: {missing_ids}"
        )

    # 添加角色（增量，不覆盖）
    existing_role_ids = [r.id for r in user.role]
    new_role_ids = [rid for rid in existing_role_ids if rid not in role_data.role_ids]
    all_role_ids = list(set(existing_role_ids + role_data.role_ids))

    all_roles = db.query(Role).filter(Role.id.in_(all_role_ids)).all()
    user.role = all_roles
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.role],
        role_names=[role.name for role in user.role]
    )


@router.delete("/{user_id}/role", response_model=UserRoleResponse)
def remove_user_role(user_id: int, role_data: UserRoleBindRequest, db: Session = Depends(get_db)):
    """移除用户角色"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 只保留不在role_data.role_ids中的角色
    remaining_role_ids = [r.id for r in user.roles if r.id not in role_data.role_ids]

    if remaining_role_ids:
        remaining_roles = db.query(Role).filter(Role.id.in_(remaining_role_ids)).all()
        user.roles = remaining_roles
    else:
        user.roles = []

    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.roles],
        role_names=[role.name for role in user.roles]
    )


@router.post("/{user_id}/password", response_model=Message)
def change_password(user_id: int, request: ChangePasswordRequest, db: Session = Depends(get_db)):
    """
    修改指定用户的密码（管理员操作）

    - 需要验证旧密码
    - 新密码不能为空
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 验证旧密码
    if not verify_password(request.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码错误"
        )

    # 验证新密码
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
    当前登录用户修改自己的密码

    - 需要验证旧密码
    - 新密码不能为空且至少6位
    """
    # 验证旧密码
    if not verify_password(request.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码错误"
        )

    # 验证新密码
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
def get_online_users(db: Session = Depends(get_db)):
    """
    获取当前在线用户列表

    返回所有状态为active且未过期的会话
    """
    # 先清理过期会话
    cleanup_expired_sessions(db)

    # 获取所有活跃会话
    now = datetime.utcnow()
    active_sessions = db.query(UserSession).filter(
        UserSession.status == "active",
        UserSession.expires_at > now
    ).order_by(UserSession.last_active_at.desc()).all()

    # 构建在线用户列表（一个用户可能有多个会话）
    online_users = []
    seen_user_ids = set()

    for session in active_sessions:
        # 去重：同一用户多个会话只显示最近的一个
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
def get_user_sessions(user_id: int, db: Session = Depends(get_db)):
    """
    获取指定用户的所有会话

    返回该用户的所有活跃和过期会话
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 先清理过期会话
    cleanup_expired_sessions(db)

    # 获取用户会话
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
def revoke_user_sessions(user_id: int, db: Session = Depends(get_db)):
    """
    撤销指定用户的所有会话（踢下线）

    将该用户的所有活跃会话标记为revoked
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 撤销所有活跃会话
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.status == "active"
    ).all()

    for session in active_sessions:
        session.status = "revoked"

    db.commit()

    return {"message": f"已撤销用户 {user.username} 的所有会话"}