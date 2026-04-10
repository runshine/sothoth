"""
工作流引擎数据模型
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AtomicWorkflowState(Enum):
    """原子工作流状态"""
    CREATED = "created"
    START_PLUGINS = "start_plugins"
    WORKER = "worker"
    REFLECT = "reflect"
    SUMMARY = "summary"
    GLOBAL_REVIEW = "global_review"
    RESULT_REVIEW = "result_review"
    END_PLUGINS = "end_plugins"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskItem:
    """任务项 — 阶段间传递"""
    id: str
    file: str                    # 任务 MD 文件路径
    source_stage: str = ""       # 来源阶段

    def __repr__(self) -> str:
        return f"TaskItem(id={self.id}, file={self.file})"


@dataclass
class AtomicWorkflowResult:
    """原子工作流执行结果"""
    status: str                  # "completed" | "failed"
    next_tasks: list[TaskItem] = field(default_factory=list)
    working_dir: str = ""
    error: Optional[str] = None
    action: str = ""             # "restart_workflow" 等特殊动作
    cycles_used: int = 0

    @property
    def success(self) -> bool:
        return self.status == "completed"


@dataclass
class CompositeWorkflowResult:
    """组合工作流执行结果"""
    status: str                  # "completed" | "failed"
    final_tasks: list[TaskItem] = field(default_factory=list)
    working_dir: str = ""
    error: Optional[str] = None
    completed_stages: list[str] = field(default_factory=list)
    total_stages: int = 0
    total_tasks_processed: int = 0

    @property
    def success(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "working_dir": self.working_dir,
            "error": self.error,
            "completed_stages": self.completed_stages,
            "total_stages": self.total_stages,
            "total_tasks_processed": self.total_tasks_processed,
            "final_task_count": len(self.final_tasks),
        }


@dataclass
class WorkflowContext:
    """原子工作流执行上下文"""
    workflow_id: str
    task_id: str
    task_file: str
    working_dir: str
    cycle: int = 0

    # Worker 会话管理
    worker_session_id: Optional[str] = None

    # 评审参谋会话管理 {advisor_instance_id → session_id}
    advisor_sessions: dict[str, str] = field(default_factory=dict)

    # 产物路径
    summary_file: Optional[str] = None
    results_dir: Optional[str] = None

    # 评审失败的结果项（传给下一轮 Worker）
    failed_result_items: list = field(default_factory=list)
