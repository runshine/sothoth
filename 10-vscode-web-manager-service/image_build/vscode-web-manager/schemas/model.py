"""
Pydantic模型定义
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ============ 用户相关 ============

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=100)
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ============ 项目相关 ============

class ProjectCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    status: str
    file_count: int
    total_size: int
    pvc_name: Optional[str]
    pvc_status: str
    file_synced: bool
    created_at: datetime
    initialized_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============ Code-Server相关 ============

class CodeServerCreate(BaseModel):
    password: Optional[str] = None
    cpu_limit: str = "1000m"
    memory_limit: str = "1024Mi"


class CodeServerUpdate(BaseModel):
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None


class CodeServerResponse(BaseModel):
    id: str
    project_id: str
    project_name: str
    status: str
    access_url: Optional[str]
    password: Optional[str]
    deployment_name: Optional[str]
    service_name: Optional[str]
    pvc_name: Optional[str]
    pod_name: Optional[str]
    pod_status: Optional[str]
    cpu_limit: str
    memory_limit: str
    created_at: datetime
    started_at: Optional[datetime]
    stopped_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============ CodeWiki相关 ============

class CodeWikiCreate(BaseModel):
    api_key: Optional[str] = None
    cpu_limit: str = "1000m"
    memory_limit: str = "2048Mi"


class CodeWikiUpdate(BaseModel):
    api_key: Optional[str] = None
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None


class CodeWikiResponse(BaseModel):
    id: str
    project_id: str
    project_name: str
    status: str
    access_url: Optional[str]
    api_key: Optional[str]
    deployment_name: Optional[str]
    service_name: Optional[str]
    pvc_name: Optional[str]
    pod_name: Optional[str]
    pod_status: Optional[str]
    cpu_limit: str
    memory_limit: str
    created_at: datetime
    started_at: Optional[datetime]
    stopped_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============ 任务相关 ============

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str

    class Config:
        from_attributes = True


# ============ 文件相关 ============

class FileResponse(BaseModel):
    path: str
    name: str
    size: int
    type: str


class DownloadResponse(BaseModel):
    file_path: str
    file_name: str
    file_type: str


# ============ PVC相关 ============

class PVCCreate(BaseModel):
    storage_size: str = "5Gi"


class PVCResponse(BaseModel):
    name: str
    status: str
    capacity: Optional[str]
    access_modes: List[str]
    size: str


# ============ 通用响应 ============

class StatusResponse(BaseModel):
    status: str
    message: str
    details: Optional[dict] = None


class ErrorResponse(BaseModel):
    error: str
    details: Optional[dict] = None