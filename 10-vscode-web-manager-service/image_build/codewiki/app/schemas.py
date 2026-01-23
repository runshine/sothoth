# app/schemas.py
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class TaskCreate(BaseModel):
    """创建任务的请求模型"""
    include: Optional[List[str]] = Field(
        default=None,
        description="文件包含模式，如 ['*.py', 'src/**/*.ts']"
    )
    exclude: Optional[List[str]] = Field(
        default=None,
        description="文件排除模式，如 ['Tests', '*.test.js']"
    )
    folder: Optional[str] = Field(
        default=".",
        description="工作目录，默认为当前目录"
    )
    config_overrides: Optional[Dict[str, Any]] = Field(
        default=None,
        description="配置覆盖项"
    )


class TaskResponse(BaseModel):
    """任务创建响应模型"""
    task_id: str
    status: str
    message: str


class Task(BaseModel):
    """任务模型"""
    id: str
    status: str
    include_patterns: Optional[List[str]]
    exclude_patterns: Optional[List[str]]
    folder: str
    config_overrides: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class ConfigUpdate(BaseModel):
    """配置更新模型"""
    config: Dict[str, Any] = Field(
        ...,
        description="配置键值对，如 {'api_key': 'xxx', 'base_url': 'https://...'}"
    )


class ConfigResponse(BaseModel):
    """配置响应模型"""
    config: Dict[str, Any]
    message: str


class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str
    timestamp: datetime
    active_tasks: int


class LogResponse(BaseModel):
    """日志响应模型"""
    task_id: str
    total_lines: int
    lines: int
    logs: str


class LogLine(BaseModel):
    """日志行模型"""
    line: int
    content: str
    level: str
    timestamp: Optional[str] = None
    file: Optional[str] = None


class LogContent(BaseModel):
    """日志内容响应模型"""
    file: str
    total_lines: int
    returned_lines: int
    lines: int
    search: Optional[str] = None
    level: Optional[str] = None
    content: List[LogLine]
    file_size: int
    last_modified: str


class LogFileInfo(BaseModel):
    """日志文件信息模型"""
    name: str
    path: str
    size: int
    size_human: str
    modified: str
    modified_human: str
    created: str
    type: str


class LogStats(BaseModel):
    """日志统计信息模型"""
    total_files: int
    total_size: int
    total_size_human: str
    type_stats: Dict[str, int]
    level_stats: Dict[str, int]
    oldest_log: Optional[str]
    newest_log: Optional[str]


class ServerLogsResponse(BaseModel):
    """服务器日志响应模型"""
    total_files: int
    files_read: int
    total_lines: int
    lines: int
    search: Optional[str] = None
    level: Optional[str] = None
    content: List[LogLine]


class DeleteOldLogsResponse(BaseModel):
    """删除旧日志响应模型"""
    deleted: List[str]
    failed: List[Dict[str, str]]
    cutoff_date: str
    days_retained: int


class LogFilesResponse(BaseModel):
    """日志文件列表响应"""
    logs_dir: str
    total_files: int
    files: List[LogFileInfo]