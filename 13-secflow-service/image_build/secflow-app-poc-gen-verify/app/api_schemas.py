"""Pydantic request/response models for the PoC-gen-verify service."""
from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


TaskStatus = Literal["pending", "running", "succeeded", "failed", "timeout", "cancelled"]
EffortLevel = Literal["low", "medium", "high", "xhigh", "max"]


class PocTaskRequest(BaseModel):
    """Frontend → microservice payload. Unpacked into `poc` CLI args."""
    model_config = ConfigDict(extra="allow")

    project_id: str = Field(..., description="项目 ID (任务归属)")
    task_name: Optional[str] = Field(None, description="任务名; 为空则自动生成")
    task_description: Optional[str] = None
    entry_function: Optional[str] = Field(None, description="数据流入口函数 (poc -e); 省略则 Stage0 从漏洞报告提取")
    vuln_report_path: str = Field(..., description="漏洞报告路径 (poc -r)")
    binary_dir: str = Field(..., description="全二进制文件目录 (poc -b)")
    output_dir: Optional[str] = Field(None, description="输出目录 (poc -o); 为空则服务生成时间戳目录")
    model: Optional[str] = Field(None, description="模型覆盖 (默认 glm-5.2)")
    effort: Optional[EffortLevel] = Field(None, description="effort level (传给 claude --effort)")
    session_name: Optional[str] = Field(None, description="会话名 (传给 claude -n)")
    session_id: Optional[str] = Field(None, description="会话 UUID (传给 claude --session-id)")
    session_dir: Optional[str] = Field(None, description="会话存储目录 (传给 poc --session-dir)")
    timeout: Optional[int] = None
    created_by: Optional[str] = None


class PocTaskCreateResponse(BaseModel):
    task_id: str
    status: TaskStatus
    output_dir: str
    log_path: Optional[str] = None


class PocTaskStatus(BaseModel):
    task_id: str
    project_id: str
    task_name: str
    task_description: Optional[str] = None
    entry_function: Optional[str] = None
    vuln_report_path: str
    binary_dir: str
    output_dir: str
    model: Optional[str] = None
    effort: Optional[str] = None
    session_name: Optional[str] = None
    session_id: Optional[str] = None
    session_dir: Optional[str] = None
    timeout: Optional[int] = None  # legacy field (unused — no timeout mechanism)
    cli_command: Optional[str] = None
    status: TaskStatus
    error: Optional[str] = None
    returncode: Optional[int] = None
    artifacts: List[str] = Field(default_factory=list)
    result_json: Optional[Dict[str, Any]] = None
    stages_json: Optional[Dict[str, Any]] = None
    # PoC outcome path (derived from Stage2 poc_report.md):
    # "a" = path A (vuln confirmed, PoC triggered successfully)
    # "b" = path B (false positive / unreachable proved)
    # None = Stage1 failed / no Stage2 report
    poc_path: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    execution_epoch: int = 0
    control_version: int = 0
    dispatch_status: Optional[str] = None
    celery_task_id: Optional[str] = None
    log_path: Optional[str] = None
    is_deleted: bool = False


class PocTaskListResponse(BaseModel):
    items: List[PocTaskStatus]
    total: int
    page: int
    per_page: int


class PocTaskStatsResponse(BaseModel):
    total: int = 0
    pending: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    timeout: int = 0  # legacy (unused — no timeout mechanism)
    cancelled: int = 0


class PocTaskLogsResponse(BaseModel):
    task_id: str
    status: TaskStatus
    returncode: Optional[int] = None
    log_path: str
    log_tail: str


class PocTaskTimelineResponse(BaseModel):
    task_id: str
    events: List[Dict[str, Any]]


class PocArtifactsResponse(BaseModel):
    task_id: str
    output_dir: str
    artifacts: List[str]
    on_disk: List[str]


class PocArtifactContentResponse(BaseModel):
    task_id: str
    name: str
    content: str
    size: int


class PocSessionFile(BaseModel):
    name: str
    rel_path: str
    size: int
    mtime: float
    kind: str
    stage: str
    claude_cmd: str = ""
    session_id: str = ""
    jsonl: str = ""
    prompt_file: str = ""
    is_active: bool = False


class PocSessionListResponse(BaseModel):
    task_id: str
    output_dir: str
    sessions: List[PocSessionFile]


class PocSessionContentResponse(BaseModel):
    task_id: str
    rel_path: str
    name: str
    content: str
    size: int
    tail_lines: int


class ActionResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str
