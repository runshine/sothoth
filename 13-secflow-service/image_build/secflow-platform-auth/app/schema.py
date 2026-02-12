"""Pydantic模式定义"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


# ============ 基础模式 ============

class UserBase(BaseModel):
    """用户基础模式"""
    username: str


class UserCreate(UserBase):
    """创建用户模式"""
    password: str
    role_ids: Optional[List[int]] = None


class UserUpdate(BaseModel):
    """更新用户模式"""
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """用户响应模式"""
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    role: List[str] = []

    class Config:
        from_attributes = True


class UserDetailResponse(UserResponse):
    """用户详细响应模式"""
    role_ids: List[int] = []


# ============ 角色模式 ============

class RoleBase(BaseModel):
    """角色基础模式"""
    name: str
    description: Optional[str] = None


class RoleCreate(RoleBase):
    """创建角色模式"""
    pass


class RoleUpdate(RoleBase):
    """更新角色模式"""
    pass


class RoleResponse(RoleBase):
    """角色响应模式"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RoleWithUsersResponse(RoleResponse):
    """带用户列表的角色响应模式"""
    user_ids: List[int] = []


# ============ 认证模式 ============

class LoginRequest(BaseModel):
    """登录请求模式"""
    username: str
    password: str


class MachineTokenRequest(BaseModel):
    """机机Token请求模式"""
    machine_code: str
    description: Optional[str] = None


class TokenResponse(BaseModel):
    """Token响应模式"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # 过期时间（秒）


class MachineTokenCreate(BaseModel):
    """创建机机Token模式"""
    machine_code: str
    description: Optional[str] = None
    expires_at: Optional[datetime] = None  # null表示永不过期


class MachineTokenResponse(BaseModel):
    """机机Token响应模式"""
    id: int
    machine_code: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============ 用户角色绑定模式 ============

class UserRoleBindRequest(BaseModel):
    """用户角色绑定请求模式"""
    role_ids: List[int]


class UserRoleResponse(BaseModel):
    """用户角色响应模式"""
    user_id: int
    role_ids: List[int]
    role_names: List[str]

    class Config:
        from_attributes = True


# ============ 在线用户/会话模式 ============

class UserSessionResponse(BaseModel):
    """用户会话响应模式"""
    id: int
    user_id: int
    username: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    status: str
    created_at: datetime
    last_active_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class OnlineUserResponse(BaseModel):
    """在线用户响应模式"""
    user_id: int
    username: str
    role: List[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    login_at: datetime
    last_active_at: datetime


class ChangePasswordRequest(BaseModel):
    """修改密码请求模式"""
    old_password: str
    new_password: str


class ChangeOwnPasswordRequest(BaseModel):
    """用户修改自己密码请求模式"""
    old_password: str
    new_password: str


# ============ 通用模式 ============

class Message(BaseModel):
    """通用消息模式"""
    message: str


class ErrorResponse(BaseModel):
    """错误响应模式"""
    detail: str