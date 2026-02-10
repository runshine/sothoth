"""
SecMate-NG Manager - Pydantic Schemas
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


# ============ PVC相关Schema ============

class PVCMount(BaseModel):
    """PVC挂载配置"""
    pvc_name: str = Field(..., description="PVC名称")
    mount_path: str = Field(..., description="挂载路径")


class OutputPVCMount(PVCMount):
    """输出PVC挂载配置"""
    pvc_name: Optional[str] = Field(None, description="PVC名称，如果不存在则自动创建")
    mount_path: str = Field(..., description="挂载路径")
    storage_size: Optional[str] = Field(None, description="存储大小，覆盖默认配置")


# ============ SecMate-NG环境变量Schema ============

class SecMateNGEnvResponse(BaseModel):
    """SecMate-NG环境变量响应"""
    PUID: int
    PGID: int
    TZ: str
    PASSWORD: Optional[str] = None
    HASHED_PASSWORD: Optional[str] = None
    SUDO_PASSWORD: Optional[str] = None
    SUDO_PASSWORD_HASH: Optional[str] = None
    PROXY_DOMAIN: Optional[str] = None
    DEFAULT_WORKSPACE: str
    PWA_APPNAME: str


# ============ SecMate-NG相关Schema ============

class SecMateNGCreateRequest(BaseModel):
    """创建SecMate-NG请求"""
    name: str = Field(..., description="SecMate-NG实例名称", min_length=1, max_length=64)
    namespace: str = Field(..., description="目标K8S Namespace")
    description: Optional[str] = Field(None, description="描述")
    source_pvcs: List[PVCMount] = Field(..., description="源码PVC列表（必须存在）")
    output_pvcs: List[OutputPVCMount] = Field(default=[], description="输出PVC列表（不存在则创建）")
    custom_env: Optional[Dict[str, str]] = Field(None, description="自定义环境变量")
    # SecMate-NG专属环境变量
    secmate_ng_env: Optional[Dict[str, Any]] = Field(None, description="SecMate-NG镜像环境变量配置（PUID, PGID, TZ, PASSWORD, SUDO_PASSWORD等）")
    # 自定义镜像
    image: Optional[str] = Field(None, description="自定义镜像地址，使用特定镜像创建SecMate-NG")


class SecMateNGDeleteRequest(BaseModel):
    """删除SecMate-NG请求"""
    name: str = Field(..., description="SecMate-NG实例名称")
    delete_output_pvcs: bool = Field(False, description="是否删除输出PVC")


class SecMateNGRestartRequest(BaseModel):
    """重建SecMate-NG请求"""
    name: str = Field(..., description="SecMate-NG实例名称")


class SecMateNGResponse(BaseModel):
    """SecMate-NG响应"""
    id: str
    project_id: str
    name: str
    namespace: str
    status: str
    source_pvcs: List[Dict[str, Any]]
    output_pvcs: List[Dict[str, Any]]
    deployment_name: Optional[str]
    service_name: Optional[str]
    ingress_name: Optional[str]
    pod_name: Optional[str]
    access_url: Optional[str]
    secmate_ng_env: Optional[Dict[str, Any]] = None  # SecMate-NG环境变量
    description: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]

    class Config:
        from_attributes = True


class SecMateNGListResponse(BaseModel):
    """SecMate-NG列表响应"""
    total: int
    items: List[SecMateNGResponse]


class SecMateNGStatusResponse(BaseModel):
    """SecMate-NG状态响应"""
    id: str
    name: str
    namespace: str
    status: str
    pod_status: Optional[str]
    pod_ip: Optional[str]
    node_name: Optional[str]
    access_url: Optional[str]
    ready_replicas: int
    total_replicas: int


# ============ 日志相关Schema ============

class SecMateNGLogsRequest(BaseModel):
    """获取日志请求"""
    tail_lines: int = Field(100, description="返回行数", ge=1, le=10000)
    container: Optional[str] = Field(None, description="容器名称")


class SecMateNGLogsResponse(BaseModel):
    """SecMate-NG日志响应"""
    secmate_ng_id: str
    secmate_ng_name: str
    namespace: str
    pod_name: str
    container: Optional[str]
    logs: str


# ============ 任务相关Schema ============

class TaskResponse(BaseModel):
    """任务响应"""
    id: str
    project_id: str
    type: str
    status: str
    secmate_ng_id: Optional[str]
    secmate_ng_name: Optional[str]
    params: Dict[str, Any]
    result: Optional[str]
    error_message: Optional[str]
    created_at: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]

    class Config:
        from_attributes = True


class TaskListResponse(BaseModel):
    """任务列表响应"""
    total: int
    items: List[TaskResponse]


class TaskDeleteResponse(BaseModel):
    """任务删除响应"""
    message: str
    deleted_id: str


# ============ 通用响应Schema ============

class SuccessResponse(BaseModel):
    """通用成功响应"""
    message: str
    data: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """通用错误响应"""
    error: str
    detail: Optional[str] = None


class TaskCreatedResponse(BaseModel):
    """任务创建响应"""
    message: str
    task_id: str
    task_type: str
