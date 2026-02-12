"""认证路由"""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
import secrets

from app.database import get_db
from app.auth import create_access_token, decode_access_token, verify_machine_token, create_human_token, create_human_token_with_session
from app.schema import (
    LoginRequest, TokenResponse, MachineTokenRequest, MachineTokenCreate,
    MachineTokenResponse, Message, UserResponse
)
from app.model import User, MachineToken

router = APIRouter(tags=["认证"])


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, request_obj: Request, db: Session = Depends(get_db)):
    """
    用户登录，获取人机Token

    通过用户名密码换取JWT Token，有效期24小时
    同时创建用户会话用于追踪在线状态
    """
    # 获取客户端信息
    ip_address = request_obj.client.host if request_obj.client else None
    user_agent = request_obj.headers.get("user-agent")

    # 使用新的带会话创建功能的登录方法
    result = create_human_token_with_session(
        db=db,
        username=request.username,
        password=request.password,
        ip_address=ip_address,
        user_agent=user_agent
    )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "access_token": result["access_token"],
        "token_type": "bearer",
        "expires_in": 86400  # 24小时 = 86400秒
    }


@router.post("/machine-token", response_model=MachineTokenResponse)
def create_machine_token(request: MachineTokenRequest, db: Session = Depends(get_db)):
    """
    申请机机Token

    通过机器码换取机机Token，机机Token用于服务间调用
    """
    # 检查是否已存在该机器码的token
    existing = db.query(MachineToken).filter(
        MachineToken.machine_code == request.machine_code
    ).first()

    if existing:
        if existing.expires_at and existing.expires_at < datetime.utcnow():
            # 已过期，删除旧token
            db.delete(existing)
            db.commit()
        elif existing.is_active:
            # 返回现有token
            return existing

    # 生成随机token
    token_value = secrets.token_urlsafe(64)

    # 创建新的机机Token
    db_token = MachineToken(
        machine_code=request.machine_code,
        description=request.description,
        token=token_value
    )

    db.add(db_token)
    db.commit()
    db.refresh(db_token)

    return db_token


@router.get("/verify", response_model=Message)
def verify_token(db: Session = Depends(get_db)):
    """
    验证并刷新人机Token

    用于保持token活跃
    """
    return {"message": "Token有效"}


@router.get("/machine-tokens", response_model=List[MachineTokenResponse])
def list_machine_tokens(db: Session = Depends(get_db)):
    """
    获取所有机机Token列表

    仅管理员使用
    """
    tokens = db.query(MachineToken).all()
    return tokens


@router.delete("/machine-tokens/{token_id}", response_model=Message)
def delete_machine_token(token_id: int, db: Session = Depends(get_db)):
    """
    删除机机Token
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    db.delete(token)
    db.commit()

    return {"message": "Token已删除"}


@router.post("/validate-human-token", response_model=UserResponse)
def validate_human_token(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    验证人机Token

    用于外部服务验证用户Token的有效性
    - 验证Token格式
    - 验证Token是否过期
    - 验证用户是否存在且已激活

    请求头示例：
    Authorization: Bearer <human_token>
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if authorization is None:
        raise credentials_exception

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
    except ValueError:
        raise credentials_exception

    # 解码Token
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token无效或已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 验证Token类型
    token_type = payload.get("type")
    if token_type != "human":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的Token类型，需要人机Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 获取用户信息
    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户不存在",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户已被禁用",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 返回用户信息
    return user


@router.post("/validate-machine-token", response_model=MachineTokenResponse)
def validate_machine_token(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    验证机机Token

    用于外部服务验证机机Token的有效性
    - 验证Token是否在数据库中
    - 验证Token是否激活
    - 验证Token是否在有效期内

    请求头示例：
    Authorization: Bearer <machine_token>
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if authorization is None:
        raise credentials_exception

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
    except ValueError:
        raise credentials_exception

    # 验证机机Token
    db_token = verify_machine_token(db, token)
    if db_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="机机Token无效、已过期或已被禁用",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return db_token