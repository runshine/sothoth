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