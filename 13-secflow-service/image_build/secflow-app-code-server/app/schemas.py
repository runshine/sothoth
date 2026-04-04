"""
Code Server Manager - Pydantic Schemas
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class LlmProviderFileBinding(BaseModel):
    name: str
    path: str
    content: str
    format: str = "other"
    enabled: bool = True
    provider_key: Optional[str] = None


class LlmFileOverride(BaseModel):
    path: str
    content: str


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


# ============ Code Server环境变量Schema ============

class CodeServerEnvResponse(BaseModel):
    """Code Server环境变量响应"""
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


# ============ Code Server相关Schema ============

class CodeServerCreateRequest(BaseModel):
    """创建Code Server请求"""
    name: str = Field(..., description="Code Server实例名称", min_length=1, max_length=64)
    namespace: Optional[str] = Field(None, description="目标K8S Namespace（已废弃，后端按 project_id 查询）")
    description: Optional[str] = Field(None, description="描述")
    source_pvcs: List[PVCMount] = Field(..., description="源码PVC列表（必须存在）")
    output_pvcs: List[OutputPVCMount] = Field(default=[], description="输出PVC列表（不存在则创建）")
    env: Dict[str, str] = Field(default_factory=dict, description="统一环境变量")
    # Code Server专属环境变量
    code_server_env: Optional[Dict[str, Any]] = Field(None, description="Code Server镜像环境变量配置（PUID, PGID, TZ, PASSWORD, SUDO_PASSWORD等）")
    # 自定义镜像
    image: Optional[str] = Field(None, description="自定义镜像地址，使用特定镜像创建Code Server")
    llm_provider_key: Optional[str] = Field(None, description="可选，配置中心 LLM Provider Key")
    llm_provider_keys: Optional[List[str]] = Field(None, description="可选，按顺序绑定多个配置中心 LLM Provider Key")
    llm_file_overrides: Optional[List[LlmFileOverride]] = Field(None, description="可选，按 path 覆盖 LLM Provider 文件内容")


class CodeServerDeleteRequest(BaseModel):
    """删除Code Server请求"""
    name: str = Field(..., description="Code Server实例名称")
    delete_output_pvcs: bool = Field(False, description="是否删除输出PVC")


class CodeServerRestartRequest(BaseModel):
    """重建Code Server请求"""
    name: str = Field(..., description="Code Server实例名称")


class CodeServerResponse(BaseModel):
    """Code Server响应"""
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
    code_server_env: Optional[Dict[str, Any]] = None  # Code Server环境变量
    llm_provider_key: Optional[str] = None
    llm_provider_keys: List[str] = Field(default_factory=list)
    llm_provider_snapshot: Optional[Dict[str, Any]] = None
    llm_provider_snapshots: List[Dict[str, Any]] = Field(default_factory=list)
    llm_provider_mapped_env_keys: List[str] = Field(default_factory=list)
    llm_file_bindings: List[LlmProviderFileBinding] = Field(default_factory=list)
    llm_configmap_name: Optional[str] = None
    description: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]

    class Config:
        from_attributes = True


class CodeServerListResponse(BaseModel):
    """Code Server列表响应"""
    total: int
    items: List[CodeServerResponse]


class CodeServerStatusResponse(BaseModel):
    """Code Server状态响应"""
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


class CodeServerDeployDefaultsResponse(BaseModel):
    """部署默认配置响应"""
    default_image: str
    preset_env: Dict[str, str] = Field(default_factory=dict)


# ============ 日志相关Schema ============

class CodeServerLogsRequest(BaseModel):
    """获取日志请求"""
    tail_lines: int = Field(100, description="返回行数", ge=1, le=10000)
    container: Optional[str] = Field(None, description="容器名称")


class CodeServerLogsResponse(BaseModel):
    """Code Server日志响应"""
    code_server_id: str
    code_server_name: str
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
    code_server_id: Optional[str]
    code_server_name: Optional[str]
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
