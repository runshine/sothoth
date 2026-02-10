"""用户路由"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_password_hash, verify_password
from app.schema import (
    UserCreate, UserUpdate, UserResponse, UserDetailResponse,
    UserRoleBindRequest, UserRoleResponse, Message
)
from app.model import User, Role

router = APIRouter(tags=["用户管理"])


@router.get("", response_model=List[UserResponse])
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
        user.role = roles

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
        role_ids=[role.id for role in user.role],
        role_names=[role.name for role in user.role]
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
    remaining_roles_ids = [r.id for r in user.role if r.id not in role_data.role_ids]

    if remaining_role_ids:
        remaining_roles = db.query(Role).filter(Role.id.in_(remaining_role_ids)).all()
        user.role = remaining_role
    else:
        user.role = []

    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return UserRoleResponse(
        user_id=user.id,
        role_ids=[role.id for role in user.role],
        role_names=[role.name for role in user.role]
    )


@router.post("/{user_id}/password", response_model=Message)
def change_password(user_id: int, request: dict, db: Session = Depends(get_db)):
    """修改密码"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    new_password = request.get("new_password")
    if not new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能为空"
        )

    user.hashed_password = get_password_hash(new_password)
    user.updated_at = datetime.utcnow()

    db.commit()

    return {"message": "密码已修改"}