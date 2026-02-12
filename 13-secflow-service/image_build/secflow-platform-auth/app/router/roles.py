"""角色路由"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.schema import (
    RoleCreate, RoleUpdate, RoleResponse, RoleWithUsersResponse, Message
)
from app.model import Role, User

router = APIRouter(tags=["角色管理"])


@router.get("/role_list", response_model=List[RoleResponse])
def list_role(db: Session = Depends(get_db)):
    """获取角色列表"""
    roles = db.query(Role).all()
    return roles


@router.get("/{role_id}", response_model=RoleWithUsersResponse)
def get_role(role_id: int, db: Session = Depends(get_db)):
    """获取单个角色"""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在"
        )

    return RoleWithUsersResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        created_at=role.created_at,
        updated_at=role.updated_at,
        user_ids=[user.id for user in role.users]
    )


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_role(role_data: RoleCreate, db: Session = Depends(get_db)):
    """创建角色"""
    # 检查角色名是否已存在
    existing = db.query(Role).filter(Role.name == role_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="角色名已存在"
        )

    role = Role(
        name=role_data.name,
        description=role_data.description
    )

    db.add(role)
    db.commit()
    db.refresh(role)

    return role


@router.put("/{role_id}", response_model=RoleResponse)
def update_role(role_id: int, role_data: RoleUpdate, db: Session = Depends(get_db)):
    """更新角色"""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在"
        )

    # 检查新角色名是否被其他角色使用
    if role_data.name:
        existing = db.query(Role).filter(
            Role.name == role_data.name,
            Role.id != role_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="角色名已存在"
            )
        role.name = role_data.name

    if role_data.description is not None:
        role.description = role_data.description

    role.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(role)

    return role


@router.delete("/{role_id}", response_model=Message)
def delete_role(role_id: int, db: Session = Depends(get_db)):
    """删除角色"""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="角色不存在"
        )

    db.delete(role)
    db.commit()

    return {"message": "角色已删除"}