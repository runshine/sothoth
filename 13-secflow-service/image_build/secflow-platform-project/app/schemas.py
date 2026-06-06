"""
Pydantic模式定义模块
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ============ 项目模式 ============

class ProjectCreate(BaseModel):
    """创建项目请求"""
    name: str = Field(..., min_length=1, max_length=128, description="项目名称")
    description: Optional[str] = Field(None, description="项目描述")
    k8s_namespace: Optional[str] = Field(None, description="关联的K8S Namespace名称")
    is_public: bool = Field(default=False, description="是否公开，False为私有，True为公开")
    department_id: Optional[int] = Field(None, description="项目归属部门ID")
    product_version_id: str = Field(..., min_length=1, max_length=32, description="产品版本ID")


class ProjectUpdate(BaseModel):
    """修改项目请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=128, description="项目名称")
    description: Optional[str] = Field(None, description="项目描述")
    k8s_namespace: Optional[str] = Field(None, description="关联的K8S Namespace名称")
    is_public: Optional[bool] = Field(None, description="是否公开，False为私有，True为公开")
    department_id: Optional[int] = Field(None, description="项目归属部门ID")
    product_version_id: Optional[str] = Field(None, min_length=1, max_length=32, description="产品版本ID")


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
    is_public: bool = Field(default=False, description="是否公开，False为私有，True为公开")
    department_id: Optional[int] = None
    department_name: Optional[str] = None
    product_id: Optional[str] = None
    product_name: Optional[str] = None
    product_path: Optional[str] = None
    product_version_id: Optional[str] = None
    product_version_name: Optional[str] = None
    product_version: Optional[str] = None
    can_manage: bool = False
    created_at: datetime
    updated_at: datetime
    roles: List[ProjectRoleBindResponse] = []
    model_config = ConfigDict(from_attributes=True)


class ProjectListResponse(BaseModel):
    """项目列表响应"""
    total: int
    projects: List[ProjectResponse]


class ProjectAllListResponse(BaseModel):
    """项目完整列表响应（获取所有记录）"""
    code: str = Field(default="200", description="状态码")
    message: str = Field(default="success", description="消息提示")
    data: List[ProjectResponse] = Field(default_factory=list, description="项目列表数据")
    model_config = ConfigDict(from_attributes=True)


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


class ProductVersionCreate(BaseModel):
    version: str = Field(..., min_length=1, max_length=128, description="产品版本号")
    name: Optional[str] = Field(None, max_length=128, description="产品版本名称")
    description: Optional[str] = Field(None, description="产品版本描述")


class ProductVersionUpdate(BaseModel):
    version: Optional[str] = Field(None, min_length=1, max_length=128, description="产品版本号")
    name: Optional[str] = Field(None, max_length=128, description="产品版本名称")
    description: Optional[str] = Field(None, description="产品版本描述")


class ProductCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="产品名称")
    code: str = Field(..., min_length=1, max_length=128, description="产品编码")
    parent_id: Optional[str] = Field(None, max_length=32, description="父产品ID")
    description: Optional[str] = Field(None, description="产品描述")
    sort_order: int = Field(default=0, description="排序")


class ProductUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128, description="产品名称")
    code: Optional[str] = Field(None, min_length=1, max_length=128, description="产品编码")
    parent_id: Optional[str] = Field(None, max_length=32, description="父产品ID")
    description: Optional[str] = Field(None, description="产品描述")
    sort_order: Optional[int] = Field(None, description="排序")


class ProductVersionResponse(BaseModel):
    id: str
    product_id: str
    version: str
    name: Optional[str]
    description: Optional[str]
    status: str
    project_count: int = 0
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ProductTreeNodeResponse(BaseModel):
    id: str
    name: str
    code: str
    parent_id: Optional[str]
    description: Optional[str]
    sort_order: int
    status: str
    is_leaf: bool
    project_count: int = 0
    created_at: datetime
    updated_at: datetime
    children: List["ProductTreeNodeResponse"] = Field(default_factory=list)
    versions: List[ProductVersionResponse] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class ProductTreeResponse(BaseModel):
    total: int
    products: List[ProductTreeNodeResponse]


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
