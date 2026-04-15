"""
配置数据模型 — Pydantic v2

完整定义了 JSON 配置文件的所有结构，包括：
- 全局配置 (GlobalConfig)
- 基础智能体定义 (AgentDef)
- 插件定义 (PluginDef)
- 原子工作流 (AtomicWorkflowDef)
- 组合工作流 (CompositeWorkflowDef)
- 执行入口 (ExecutionConfig)
"""

from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════
# 全局配置
# ══════════════════════════════════════════

class GlobalConfig(BaseModel):
    """全局配置"""
    workspace_root: str = "/workspace"
    log_level: str = "INFO"
    max_workflow_retry: int = Field(default=3, ge=1)
    max_review_cycles: int = Field(default=10, ge=1)
    default_context_reset: bool = False
    parallel_result_review: bool = True
    parallel_result_review_limit: int = Field(default=3, ge=1)
    env_vars: dict[str, str] = Field(default_factory=dict)


# ══════════════════════════════════════════
# 基础智能体定义
# ══════════════════════════════════════════

class AgentDef(BaseModel):
    """基础智能体定义 (R2, R12)"""
    id: str
    name: str
    type: Literal["claude_code", "codex", "opencode", "pi_agent"]
    reset_context: bool = False
    runtime_config: dict[str, Any] = Field(default_factory=dict)


# ══════════════════════════════════════════
# 插件定义
# ══════════════════════════════════════════

class PluginDef(BaseModel):
    """插件定义 (R4, R5a)"""
    id: str
    name: str
    module_path: str          # Python 模块路径
    class_name: str           # 插件类名
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


# ══════════════════════════════════════════
# Worker 角色定义
# ══════════════════════════════════════════

class WorkPromptConfig(BaseModel):
    """Worker 工作 prompt 配置"""
    system_prompt_file: str
    user_prompt_file: str


class ReflectionPromptConfig(BaseModel):
    """反思 prompt 配置"""
    id: str
    prompt_file: str
    description: str = ""


class SummaryPromptConfig(BaseModel):
    """总结 prompt 配置"""
    prompt_file: str
    output_summary_filename: str = "summary.md"
    output_results_dir: str = "results"


class WorkerPromptsConfig(BaseModel):
    """Worker 全部 prompt"""
    work: WorkPromptConfig
    reflection: list[ReflectionPromptConfig] = Field(default_factory=list)
    summary: SummaryPromptConfig


class WorkerRoleDef(BaseModel):
    """Worker 角色定义 (R5b, R6c)"""
    agent_id: str
    new_session: bool = True
    reset_context_override: Optional[bool] = None
    prompts: WorkerPromptsConfig


# ══════════════════════════════════════════
# 参谋 (Advisor) 角色定义
# ══════════════════════════════════════════

class AdvisorInstanceDef(BaseModel):
    """参谋智能体实例定义 (R7)"""
    instance_id: str
    agent_id: str
    role_name: str
    re_review_on_cycle: bool   # 全局评审默认 True，结果评审默认 False
    system_prompt_file: str
    user_prompt_template: str


class AdvisorsDef(BaseModel):
    """参谋角色组定义"""
    global_review: list[AdvisorInstanceDef] = Field(default_factory=list)
    result_review: list[AdvisorInstanceDef] = Field(default_factory=list)


class RolesDef(BaseModel):
    """角色定义集合 (R5b)"""
    worker: WorkerRoleDef
    advisors: AdvisorsDef = Field(default_factory=AdvisorsDef)


# ══════════════════════════════════════════
# 原子工作流定义
# ══════════════════════════════════════════

class EngineConfig(BaseModel):
    """引擎参数"""
    max_review_cycles: Optional[int] = None
    max_worker_turns_per_cycle: int = 30


class AtomicWorkflowDef(BaseModel):
    """原子工作流定义 (R3, R4, R6)"""
    id: str
    name: str
    type: Literal["atomic"] = "atomic"
    description: str = ""
    working_dir_template: str
    start_plugins: list[str] = Field(default_factory=list)
    end_plugins: list[str] = Field(default_factory=list)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    roles: RolesDef


# ══════════════════════════════════════════
# 组合工作流定义
# ══════════════════════════════════════════

class StageDef(BaseModel):
    """阶段定义 (R9)"""
    stage_id: str
    name: str = ""
    sequence: int
    workflow_ref: str                    # 引用工作流 ID
    workflow_type: Literal["atomic", "composite"]
    on_error: Literal["abort", "skip_task", "skip_stage"] = "skip_task"
    description: str = ""


class CompositeWorkflowDef(BaseModel):
    """组合工作流定义 (R3, R9)"""
    id: str
    name: str
    type: Literal["composite"] = "composite"
    description: str = ""
    working_dir_template: str
    stages: list[StageDef]

    @field_validator("stages")
    @classmethod
    def validate_stage_sequence(cls, v: list[StageDef]) -> list[StageDef]:
        """校验 stages 按 sequence 连续递增"""
        if not v:
            raise ValueError("组合工作流必须至少有1个 stage")
        sorted_stages = sorted(v, key=lambda s: s.sequence)
        for i, stage in enumerate(sorted_stages):
            if i > 0 and stage.sequence <= sorted_stages[i - 1].sequence:
                raise ValueError(
                    f"stage sequence 必须严格递增: {stage.stage_id}")
        return sorted_stages


# ══════════════════════════════════════════
# 工作流集合
# ══════════════════════════════════════════

class WorkflowsDef(BaseModel):
    """工作流集合"""
    atomic: list[AtomicWorkflowDef] = Field(default_factory=list)
    composite: list[CompositeWorkflowDef] = Field(default_factory=list)


# ══════════════════════════════════════════
# 执行入口
# ══════════════════════════════════════════

class InputTaskConfig(BaseModel):
    """输入任务配置"""
    task_file: str
    task_id: str = "default"


class CompletionConfig(BaseModel):
    """执行完成配置"""
    exit_code_on_success: int = 0
    exit_code_on_failure: int = 1
    write_summary: bool = True
    summary_file: str = "/output/execution_summary.json"


class ExecutionConfig(BaseModel):
    """执行入口配置 (R11, R14)"""
    entry_workflow: str
    entry_workflow_type: Literal["composite"] = "composite"
    input_task: InputTaskConfig
    output_dir: str = "/output"
    execution_id: str = "default"
    runtime_mode: str = "k8s_job"
    on_completion: CompletionConfig = Field(default_factory=CompletionConfig)


# ══════════════════════════════════════════
# 顶层配置
# ══════════════════════════════════════════

class FrameworkConfig(BaseModel):
    """
    框架顶层配置 — 对应完整 JSON 文件

    所有 JSON 配置最终解析为此模型
    """
    version: str = "1.0"
    global_config: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    agents: list[AgentDef] = Field(default_factory=list)
    plugins: list[PluginDef] = Field(default_factory=list)
    workflows: WorkflowsDef = Field(default_factory=WorkflowsDef)
    execution: ExecutionConfig

    model_config = {"populate_by_name": True}
