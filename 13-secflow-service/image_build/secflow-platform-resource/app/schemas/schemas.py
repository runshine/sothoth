"""Pydantic schemas for resource management."""

from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
from app.models.database import ResourceType, TaskStatus, TaskType


class TokenPayload(BaseModel):
    """Token载荷信息。"""
    id: int
    username: Optional[str] = None
    is_active: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    role: List[str] = []


# ============ 项目相关Schema ============

class ProjectInfo(BaseModel):
    """项目信息。"""
    project_id: str
    project_name: Optional[str] = None
    description: Optional[str] = None


# ============ 资源相关Schema ============

class ResourceCreateRequest(BaseModel):
    """创建资源请求（兼容旧版接口）。"""
    name: str = Field(..., description="资源名称")
    description: Optional[str] = Field(default=None, description="资源描述")
    resource_type: ResourceType = Field(..., description="资源类型: document/software/code/other/output_pvc")
    project_ids: List[str] = Field(..., min_length=1, description="关联的项目ID列表")
    archive_url: str = Field(..., description="压缩包下载地址URL")
    pvc_size: int = Field(default=10, ge=1, le=500, description="PVC大小，默认10Gi")


class ResourceUploadRequest(BaseModel):
    """上传资源请求（通过URL下载压缩包并解压到PVC根目录）。"""
    name: str = Field(..., description="资源名称")
    description: Optional[str] = Field(default=None, description="资源描述")
    resource_type: ResourceType = Field(..., description="资源类型: document/software/code/other/output_pvc")
    # 关联的项目ID列表（至少一个）
    project_ids: List[str] = Field(..., min_length=1, description="关联的项目ID列表")
    # 压缩包URL
    archive_url: str = Field(..., description="压缩包下载地址URL")
    # PVC大小（Gi），默认10Gi
    pvc_size: int = Field(default=10, ge=1, le=500, description="PVC大小，默认10Gi")


class ResourceUploadResponse(BaseModel):
    """上传资源响应。"""
    task_id: str = Field(..., description="异步任务ID")
    resource_uuid: str = Field(..., description="资源UUID")
    message: str = Field(..., description="成功消息")


class ResourceCreateResponse(BaseModel):
    """创建资源响应。"""
    task_id: str
    resource_uuid: str
    message: str


class ResourceResponse(BaseModel):
    """资源详情响应。"""
    id: int
    resource_uuid: str
    name: str
    description: Optional[str]
    resource_type: ResourceType
    # 原始文件信息
    original_file_name: str
    original_file_size: int
    original_file_md5: Optional[str]
    original_file_format: Optional[str]
    # 上传状态
    upload_status: str
    upload_message: Optional[str]
    # PVC信息
    pvc_name: Optional[str]
    pvc_namespace: Optional[str]
    pvc_size: str
    extract_path: Optional[str]
    # 关联的项目
    project_ids: List[str]
    # 元数据
    resource_metadata: Optional[dict]
    created_by: Optional[str]
    # 时间戳
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ResourceListRequest(BaseModel):
    """资源列表请求。"""
    project_id: Optional[str] = Field(None, description="项目ID（筛选）")
    resource_type: Optional[ResourceType] = Field(None, description="资源类型筛选")
    upload_status: Optional[str] = Field(None, description="状态筛选")


class ResourceListResponse(BaseModel):
    """资源列表响应。"""
    resources: List[ResourceResponse]
    total: int


class ResourceDeleteResponse(BaseModel):
    """删除资源响应。"""
    message: str
    deleted_pvc: Optional[str] = None


# ============ 任务相关Schema ============

class TaskResponse(BaseModel):
    """任务详情响应。"""
    task_id: str
    task_uuid: str
    resource_id: Optional[int]
    project_id: Optional[str]
    task_type: TaskType
    status: TaskStatus
    progress: int
    message: Optional[str]
    error_message: Optional[str]
    input_params: Optional[dict]
    result: Optional[dict]
    created_k8s_resources: Optional[List[dict]]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TaskListRequest(BaseModel):
    """任务列表请求。"""
    project_id: Optional[str] = Field(None, description="项目ID筛选")
    resource_id: Optional[int] = Field(None, description="资源ID筛选")
    task_type: Optional[TaskType] = Field(None, description="任务类型筛选")
    status: Optional[TaskStatus] = Field(None, description="状态筛选")


class TaskListResponse(BaseModel):
    """任务列表响应。"""
    tasks: List[TaskResponse]
    total: int


class TaskLogResponse(BaseModel):
    """任务日志响应。"""
    task_id: str
    logs: List[str]


class BatchResourceCreateItem(BaseModel):
    """批量创建资源请求项。"""
    name: str = Field(..., description="资源名称")
    description: Optional[str] = Field(default=None, description="资源描述")
    resource_type: ResourceType = Field(..., description="资源类型")
    project_ids: List[str] = Field(..., min_length=1, description="关联的项目ID列表")
    archive_url: str = Field(..., description="压缩包下载地址URL")
    pvc_size: int = Field(default=10, ge=1, le=500, description="PVC大小")


class BatchResourceCreateRequest(BaseModel):
    """批量创建资源请求。"""
    items: List[BatchResourceCreateItem]


class BatchResourceCreateResponse(BaseModel):
    """批量创建资源响应。"""
    success_count: int
    total_count: int
    items: List[ResourceCreateResponse]
    errors: List[str]


class TaskDeleteResponse(BaseModel):
    """删除任务响应。"""
    message: str


# ============ PVC相关Schema ============

class PVCInfoResponse(BaseModel):
    """PVC信息响应。"""
    pvc_name: str
    namespace: str
    capacity: str
    status: str
    storage_class: str
    resource_id: Optional[int]
    resource_name: Optional[str]
    resource_type: Optional[str]


class PVCListRequest(BaseModel):
    """PVC列表请求。"""
    project_id: Optional[str] = Field(None, description="项目ID筛选")


class PVCListResponse(BaseModel):
    """PVC列表响应。"""
    pvcs: List[PVCInfoResponse]
    total: int


# ============ OutputPVC相关Schema ============

class OutputPVCCreateRequest(BaseModel):
    """创建输出PVC资源请求。"""
    name: str = Field(..., description="输出PVC资源名称")
    description: Optional[str] = Field(default=None, description="资源描述")
    project_id: str = Field(..., description="关联的项目ID")
    pvc_size: int = Field(default=10, ge=1, le=500, description="PVC大小（Gi），默认10Gi")


class OutputPVCCreateResponse(BaseModel):
    """创建输出PVC资源响应。"""
    resource_id: int
    resource_uuid: str
    pvc_name: str
    namespace: str
    capacity: str
    message: str


class OutputPVCDeleteResponse(BaseModel):
    """删除输出PVC资源响应。"""
    message: str
    deleted_pvc: Optional[str] = None


class ManualPVCCreateRequest(BaseModel):
    """手动创建PVC资源请求（支持任意资源类型）。"""
    name: str = Field(..., description="资源名称")
    description: Optional[str] = Field(default=None, description="资源描述")
    project_id: str = Field(..., description="关联项目ID")
    resource_type: ResourceType = Field(..., description="资源类型: document/software/code/other/output_pvc")
    pvc_size: int = Field(default=10, ge=1, le=500, description="PVC大小（Gi）")


class ManualPVCCreateResponse(BaseModel):
    """手动创建PVC资源响应。"""
    task_id: Optional[str] = None
    resource_id: int
    resource_uuid: str
    resource_type: ResourceType
    pvc_name: str
    namespace: str
    capacity: str
    message: str


class PvcBrowserBreadcrumbItem(BaseModel):
    """PVC 浏览器面包屑。"""
    path: str
    name: str


class PvcBrowserNode(BaseModel):
    """PVC 浏览器节点。"""
    path: str
    name: str
    node_type: str
    size: Optional[int] = None
    updated_at: Optional[int] = None
    content_type: Optional[str] = None
    has_children: bool = False
    children: List["PvcBrowserNode"] = Field(default_factory=list)


class PvcBrowserRootResponse(BaseModel):
    """PVC 浏览器根节点响应。"""
    resource_id: int
    pvc_name: str
    total: int
    items: List[PvcBrowserNode]


class PvcBrowserChildrenResponse(BaseModel):
    """PVC 浏览器目录子节点响应。"""
    resource_id: int
    pvc_name: str
    current_path: str
    breadcrumbs: List[PvcBrowserBreadcrumbItem]
    directories: List[PvcBrowserNode]
    files: List[PvcBrowserNode]


class PvcBrowserFileResponse(BaseModel):
    """PVC 浏览器文件读取响应。"""
    path: str
    filename: str
    size: int
    content_type: Optional[str] = None
    truncated: bool = False
    base64: str


class PvcBrowserUploadResponse(BaseModel):
    """PVC 浏览器上传响应。"""
    message: str
    path: str
    size: int


class OutputPVCBrowserCreateDirectoryRequest(BaseModel):
    """创建 PVC 浏览器目录。"""
    path: str = Field(default="/", description="父目录路径")
    name: str = Field(..., description="目录名称")


class OutputPVCBrowserRenameRequest(BaseModel):
    """重命名 PVC 浏览器节点。"""
    path: str = Field(..., description="当前节点路径")
    target_name: str = Field(..., description="目标名称")


class OutputPVCBrowserMoveRequest(BaseModel):
    """移动 PVC 浏览器节点。"""
    path: str = Field(..., description="当前节点路径")
    target_path: str = Field(..., description="目标目录路径")


# ============ 通用响应Schema ============

class ErrorResponse(BaseModel):
    """错误响应。"""
    detail: str


class SuccessResponse(BaseModel):
    """成功响应。"""
    message: str
    data: Optional[dict] = None


class HealthResponse(BaseModel):
    """健康检查响应。"""
    status: str
    service: str
    version: str


PvcBrowserNode.model_rebuild()
