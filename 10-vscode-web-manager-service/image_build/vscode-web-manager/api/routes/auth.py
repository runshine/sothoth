"""
认证API路由
"""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from config import Config
from database import get_db
from models import User
from schemas.models import UserCreate, UserLogin, ChangePassword
from utils.auth_utils import (
    verify_password, get_password_hash, create_access_token, get_current_user
)

router = APIRouter()

@router.post("/auth/register")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """用户注册"""
    # 检查用户名
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 检查邮箱
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="邮箱已存在")

    # 创建用户
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "注册成功",
        "user_id": user.id,
        "username": user.username
    }

@router.post("/auth/login")
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """用户登录"""
    user = db.query(User).filter(User.username == user_data.username).first()

    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="用户名或密码错误")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="用户已被禁用")

    # 创建访问令牌
    access_token_expires = timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }

@router.post("/auth/change-password")
async def change_password(
    data: ChangePassword,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """修改密码"""
    if not verify_password(data.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="旧密码错误")

    user.password_hash = get_password_hash(data.new_password)
    db.commit()

    return {"message": "密码修改成功"}

@router.get("/auth/me")
async def get_me(user: User = Depends(get_current_user)):
    """获取当前用户信息"""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": user.created_at
    }