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


class MachineTokenUpdate(BaseModel):
    """更新机机Token模式"""
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


class MachineTokenDetailResponse(MachineTokenResponse):
    """机机Token详细响应模式（包含Token值）"""
    token: str

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


# ============ 组织管理模式 ============

class DepartmentBase(BaseModel):
    """部门基础模式"""
    name: str
    description: Optional[str] = None
    parent_id: Optional[int] = None


class DepartmentCreate(DepartmentBase):
    """创建部门模式"""
    pass


class DepartmentUpdate(BaseModel):
    """更新部门模式"""
    name: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[int] = None


class DepartmentResponse(DepartmentBase):
    """部门响应模式"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DepartmentMemberBase(BaseModel):
    """部门成员基础模式"""
    user_id: int
    department_id: int
    role: str  # leader, member


class DepartmentMemberCreate(DepartmentMemberBase):
    """创建部门成员模式"""
    pass


class DepartmentMemberUpdate(BaseModel):
    """更新部门成员模式"""
    role: Optional[str] = None


class DepartmentMemberResponse(BaseModel):
    """部门成员响应模式"""
    id: int
    user_id: int
    username: str
    department_id: int
    department_name: str
    role: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProjectBase(BaseModel):
    """项目基础模式"""
    name: str
    description: Optional[str] = None
    is_public: bool = False


class ProjectCreate(ProjectBase):
    """创建项目模式"""
    department_ids: Optional[List[int]] = None


class ProjectUpdate(BaseModel):
    """更新项目模式"""
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None


class ProjectResponse(ProjectBase):
    """项目响应模式"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProjectDetailResponse(ProjectResponse):
    """项目详细响应模式"""
    departments: List[DepartmentResponse] = []


class UserPermissionInfo(BaseModel):
    """用户权限信息响应模式"""
    user_id: int
    is_admin: bool
    department_ids: List[int]
    manageable_department_ids: List[int]
    department_structure_manageable_ids: List[int]
    role_names: List[str]


# ============ Project服务相关模式 ============

class ProjectRoleBindResponse(BaseModel):
    """项目角色绑定响应模式（来自project服务）"""
    user_id: str
    role: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ProjectServiceResponse(BaseModel):
    """项目服务响应模式（来自project服务）"""
    id: str
    name: str
    description: Optional[str]
    owner_id: str
    owner_name: Optional[str]
    k8s_namespace: Optional[str]
    status: str
    is_public: bool = False
    created_at: datetime
    updated_at: datetime
    roles: List[ProjectRoleBindResponse] = []

    class Config:
        from_attributes = True


class ProjectServiceListResponse(BaseModel):
    """项目服务列表响应模式"""
    code: str = "200"
    message: str = "success"
    data: List[ProjectServiceResponse] = []

    class Config:
        from_attributes = True


class UserDepartmentProjectResponse(BaseModel):
    """用户部门相关项目响应模式"""
    id: str
    name: str
    description: Optional[str]
    owner_id: str
    owner_name: Optional[str]
    k8s_namespace: Optional[str]
    status: str
    is_public: bool
    created_at: datetime
    updated_at: datetime
    roles: List[ProjectRoleBindResponse] = []
    owner_department_id: Optional[int] = None
    owner_department_name: Optional[str] = None

    class Config:
        from_attributes = True


class UserDepartmentProjectListResponse(BaseModel):
    """用户部门相关项目列表响应模式"""
    total: int
    projects: List[UserDepartmentProjectResponse] = []