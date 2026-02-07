"""认证依赖"""

from typing import Optional
from fastapi import HTTPException, status, Depends, Header
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import decode_access_token, verify_machine_token
from app.model import User

# Token类型
TOKEN_TYPE_HUMAN = "human"
TOKEN_TYPE_MACHINE = "machine"


async def get_current_user(
        authorization: Optional[str] = Header(None),
        db: Session = Depends(get_db)
) -> User:
    """
    获取当前用户（人机token认证）

    用于需要用户身份的内部API鉴权
    验证JWT Token有效性、有效期和用户状态
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据，请提供有效的人机Token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if authorization is None:
        raise credentials_exception

    try:
        # 解析Authorization头
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
    except ValueError:
        raise credentials_exception

    # 解码token
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token无效或已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 验证Token类型
    token_type = payload.get("type")
    if token_type != TOKEN_TYPE_HUMAN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的token类型，需要人机Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    # 获取用户
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

    return user


async def get_machine_client(
        authorization: Optional[str] = Header(None),
        db: Session = Depends(get_db)
) -> bool:
    """
    验证机机token

    用于服务间调用的外部API鉴权
    验证机机Token是否在数据库中、是否激活、是否在有效期内
    """
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据，请提供有效的机机Token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if authorization is None:
        raise credential_exception

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise credential_exception
    except ValueError:
        raise credential_exception

    # 验证机机token
    db_token = verify_machine_token(db, token)
    if db_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="机机Token无效、已过期或已被禁用",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True


async def get_optional_user(
        authorization: Optional[str] = Header(None),
        db: Session = Depends(get_db)
) -> Optional[User]:
    """
    可选的用户认证（如果提供了token则验证，否则返回None）

    用于开放某些接口，允许匿名访问但支持登录后获取更多信息
    """
    if authorization is None:
        return None

    try:
        return await get_current_user(authorization, db)
    except HTTPException:
        return None