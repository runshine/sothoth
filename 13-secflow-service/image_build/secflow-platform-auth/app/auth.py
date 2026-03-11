"""认证相关功能"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import secrets
from sqlalchemy.orm import Session

from app.config import config
from app.model import User, MachineToken

# 配置
SECRET_KEY = config.get("jwt", {}).get("secret_key", "secflow-secret-key-change-in-production")
ALGORITHM = config.get("jwt", {}).get("algorithm", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = config.get("jwt", {}).get("access_token_expire_minutes", 1440)

# 密码加密
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """获取密码哈希"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """创建JWT Token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """解码JWT Token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def create_machine_token(db: Session, machine_code: str, description: Optional[str] = None,
                         expires_at: Optional[datetime] = None) -> MachineToken:
    """创建机机Token"""
    # 生成随机token
    token = secrets.token_urlsafe(64)
    db_token = MachineToken(
        token=token,
        machine_code=machine_code,
        description=description,
        expires_at=expires_at
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token


def verify_machine_token(db: Session, token: str) -> Optional[MachineToken]:
    """验证机机Token"""
    db_token = db.query(MachineToken).filter(MachineToken.token == token).first()
    if not db_token:
        return None
    if not db_token.is_active:
        return None
    if db_token.expires_at and db_token.expires_at < datetime.utcnow():
        # 如果token已过期，将状态设置为禁用并更新时间戳
        db_token.is_active = False
        db_token.updated_at = datetime.utcnow()
        db.commit()
        return None
    return db_token


def create_human_token(db: Session, username: str, password: str) -> Optional[User]:
    """通过用户名密码获取用户，返回用户用于创建token"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


def generate_token_jti() -> str:
    """生成Token唯一标识符 (JWT ID)"""
    import uuid
    return str(uuid.uuid4())


def create_human_token_with_session(db: Session, username: str, password: str,
                                    ip_address: Optional[str] = None,
                                    user_agent: Optional[str] = None) -> Optional[dict]:
    """
    用户登录并创建会话

    返回包含用户对象和token信息的字典
    """
    from app.model import UserSession

    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None

    # 生成token jti
    token_jti = generate_token_jti()

    # 计算过期时间
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.utcnow() + expires_delta

    # 创建JWT token
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "type": "human",
            "jti": token_jti  # 添加JWT ID用于会话追踪
        },
        expires_delta=expires_delta
    )

    # 创建用户会话记录
    user_session = UserSession(
        user_id=user.id,
        token_jti=token_jti,
        ip_address=ip_address,
        user_agent=user_agent,
        status="active",
        expires_at=expires_at
    )
    db.add(user_session)
    db.commit()

    return {
        "user": user,
        "access_token": access_token,
        "token_jti": token_jti,
        "expires_at": expires_at
    }


def revoke_user_session(db: Session, token_jti: str) -> bool:
    """撤销用户会话"""
    from app.model import UserSession
    session = db.query(UserSession).filter(UserSession.token_jti == token_jti).first()
    if session:
        session.status = "revoked"
        db.commit()
        return True
    return False


def cleanup_expired_sessions(db: Session) -> int:
    """清理过期的会话，返回清理数量"""
    from app.model import UserSession
    expired_sessions = db.query(UserSession).filter(
        UserSession.expires_at < datetime.utcnow(),
        UserSession.status == "active"
    ).all()

    count = 0
    for session in expired_sessions:
        session.status = "expired"
        count += 1

    db.commit()
    return count


def cleanup_expired_machine_tokens(db: Session) -> int:
    """清理过期的机机Token，返回清理数量"""
    expired_tokens = db.query(MachineToken).filter(
        MachineToken.expires_at < datetime.utcnow(),
        MachineToken.is_active == True
    ).all()

    count = 0
    for token in expired_tokens:
        # 将过期token设置为禁用
        token.is_active = False
        token.updated_at = datetime.utcnow()
        count += 1

    db.commit()
    return count