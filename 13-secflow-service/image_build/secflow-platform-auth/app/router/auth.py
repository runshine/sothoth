"""认证路由"""

import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.database import get_db
from app.dependencies import get_current_super_admin
from app.auth import create_access_token, decode_access_token, verify_machine_token, create_human_token, create_human_token_with_session, get_password_hash
from app.config import config
from app.model import Department, DepartmentMember, User, MachineToken, Role
from app.rbac import get_primary_platform_role
from app.schema import (
    LoginRequest, TokenResponse, MachineTokenRequest, MachineTokenCreate,
    MachineTokenResponse, MachineTokenDetailResponse, Message, UserResponse, UserCreate
)

router = APIRouter(tags=["认证"])


def _extract_bearer_token(authorization: Optional[str]) -> str:
    """从Authorization头中提取Bearer token。"""
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
        return token
    except ValueError:
        raise credentials_exception


def _build_human_user_payload(user: User, db: Optional[Session] = None) -> Dict[str, Any]:
    """构建统一的人类用户响应结构。"""
    membership = None
    department = None
    if db is not None:
        membership = db.query(DepartmentMember).filter(
            DepartmentMember.user_id == user.id
        ).order_by(DepartmentMember.id.asc()).first()
        if membership:
            department = db.query(Department).filter(Department.id == membership.department_id).first()

    return {
        "id": user.id,
        "username": user.username,
        "is_active": user.is_active,
        "must_change_password": bool(getattr(user, "must_change_password", False)),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "role": [r.name for r in user.roles] if getattr(user, "roles", None) else [],
        "platform_role": get_primary_platform_role(user),
        "department_member_id": membership.id if membership else None,
        "department_id": membership.department_id if membership else None,
        "department_name": department.name if department else None,
        "token_type": "human",
    }


def _build_machine_user_payload(
    machine_code: str,
    machine_token_id: Optional[int] = None,
    project_id: Optional[str] = None,
    token_scope: str = "global"
) -> Dict[str, Any]:
    """构建统一的机机主体响应结构，兼容既有依赖中的用户字段。"""
    return {
        "id": -1,
        "username": f"machine:{machine_code}",
        "is_active": True,
        "created_at": None,
        "updated_at": None,
        "role": ["machine"],
        "token_type": "machine",
        "machine_code": machine_code,
        "machine_token_id": machine_token_id,
        "project_id": project_id,
        "token_scope": token_scope,
    }


@router.get("/health")
def health():
    return {"status": "ok", **build_service_meta()}


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


@router.post("/machine-token", response_model=MachineTokenDetailResponse, status_code=status.HTTP_201_CREATED)
def create_machine_token(request: MachineTokenRequest, db: Session = Depends(get_db)):
    """
    申请机机Token

    通过机器码换取机机Token，机机Token用于服务间调用
    - 无需认证
    - 如果机器码已存在且有效，返回现有Token
    - 如果机器码已存在但已过期，重新生成Token
    - 如果机器码不存在，创建新Token
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
            # 返回现有token，包含完整token值
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
def list_machine_tokens(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    获取所有机机Token列表

    仅管理员使用
    """
    tokens = db.query(MachineToken).all()
    
    # 检查每个Token的过期状态
    now = datetime.utcnow()
    for token in tokens:
        if token.expires_at and token.expires_at < now and token.is_active:
            # 如果Token已过期且状态仍为激活，更新状态为禁用
            token.is_active = False
            token.updated_at = now
    
    # 如果有更新，提交到数据库
    db.commit()
    
    return tokens


@router.delete("/machine-tokens/{token_id}", response_model=Message)
def delete_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
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
    token = _extract_bearer_token(authorization)

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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token缺少用户标识",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
    return _build_human_user_payload(user, db)


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
    token = _extract_bearer_token(authorization)

    # 验证机机Token
    db_token = verify_machine_token(db, token)
    if db_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="机机Token无效、已过期或已被禁用",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return db_token


@router.post("/validate-token")
def validate_token(
    authorization: Optional[str] = Header(None),
    project_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    统一验证Token（人机/机机）。

    认证顺序：
    1. 人机JWT Token
    2. 数据库中的机机Token
    3. 配置中的统一机机Token（service_auth.machine_token）
    """
    token = _extract_bearer_token(authorization)

    # 1) 人机Token校验
    payload = decode_access_token(token)
    if payload is not None and payload.get("type") == "human":
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="人机Token缺少用户标识",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = db.query(User).filter(User.id == int(user_id)).first()
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="用户不存在或已被禁用",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return _build_human_user_payload(user, db)

    # 2) 机机Token（数据库）
    db_token = verify_machine_token(db, token)
    if db_token is not None:
        if project_id and db_token.token_scope == "project" and db_token.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="机机Token未绑定当前项目",
            )
        return _build_machine_user_payload(
            machine_code=db_token.machine_code,
            machine_token_id=db_token.id,
            project_id=db_token.project_id,
            token_scope=db_token.token_scope or "global",
        )

    # 3) 统一机机Token（配置）
    shared_machine_token = (
        config.get("service_auth", {}).get("machine_token")
        or config.get("service_auth", {}).get("service_machine_token")
        or ""
    )
    if shared_machine_token and secrets.compare_digest(token, shared_machine_token):
        return _build_machine_user_payload(machine_code="secflow-service-token")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token无效、已过期或未授权",
        headers={"WWW-Authenticate": "Bearer"},
    )
