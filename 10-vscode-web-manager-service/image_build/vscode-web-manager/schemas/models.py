"""
Pydantic数据模型
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

class CodeServerCreate(BaseModel):
    password: Optional[str] = None
    cpu_limit: Optional[str] = "1000m"
    memory_limit: Optional[str] = "1024Mi"

class CodeServerUpdate(BaseModel):
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None

class DownloadRequest(BaseModel):
    file_path: str  # 项目内相对文件路径

class MultiDownloadRequest(BaseModel):
    file_paths: List[str]  # 多个项目内相对文件路径

class RecreatePVCRequest(BaseModel):
    storage_size: Optional[str] = None  # 存储大小，如 "5Gi"

class ErrorResponse(BaseModel):
    message: str
    details: Optional[Dict] = None
    status_code: int = 500