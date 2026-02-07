"""
Pydantic模式定义模块
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ============ 项目模式 ============

class ProjectCreate(BaseModel):
    """创建项目请求"""
    name: str = Field(..., min_length=1, max_length=128, description="项目名称")
    description: Optional[str] = Field(None, description="项目描述")
    k8s_namespace: Optional[str] = Field(None, description="关联的K8S Namespace名称")


class ProjectUpdate(BaseModel):
    """修改项目请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=128, description="项目名称")
    description: Optional[str] = Field(None, description="项目描述")
    k8s_namespace: Optional[str] = Field(None, description="关联的K8S Namespace名称")


class ProjectRoleBindCreate(BaseModel):
    """绑定角色请求"""
    user_id: str = Field(..., description="用户ID")
    role: str = Field(..., description="角色：owner, admin, member")


class ProjectRoleBindResponse(BaseModel):
    """角色绑定响应"""
    user_id: str
    role: str
    created_at: datetime


class ProjectResponse(BaseModel):
    """项目响应"""
    id: str
    name: str
    description: Optional[str]
    owner_id: str
    owner_name: Optional[str]
    k8s_namespace: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    roles: List[ProjectRoleBindResponse] = []

    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    """项目列表响应"""
    total: int
    projects: List[ProjectResponse]


class DeleteRoleRequest(BaseModel):
    """删除角色绑定请求"""
    user_id: str = Field(..., description="用户ID")


# ============ 认证模式 ============

class TokenUser(BaseModel):
    """Token验证返回的用户信息"""
    id: str
    username: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    role: List[str]


class TokenPayload(BaseModel):
    """Token载荷"""
    user: TokenUser


# ============ 通用模式 ============

class ErrorResponse(BaseModel):
    """错误响应"""
    code: str
    message: str
    details: Optional[dict] = None


class SuccessResponse(BaseModel):
    """成功响应"""
    message: str


# ============ K8S资源模式 ============

class PodLogResponse(BaseModel):
    """Pod日志响应"""
    pod_name: str
    namespace: str
    logs: str
    container: Optional[str] = None


class ProjectResourcesResponse(BaseModel):
    """项目K8S资源响应"""
    namespace: str
    pods: List[dict]
    services: List[dict]
    configmaps: List[str]
    secrets: List[str]
    deployments: List[dict]
    statefulsets: List[dict]
    pvcs: List[dict]
    ingresses: List[dict]