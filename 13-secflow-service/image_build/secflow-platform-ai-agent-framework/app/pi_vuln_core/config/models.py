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
from pydantic import BaseModel, Field, field_validator, model_validator


# ══════════════════════════════════════════
# 全局配置
# ══════════════════════════════════════════

class GlobalConfig(BaseModel):
    """全局配置"""
    workspace_root: str = "/workspace"
    log_level: str = "INFO"
    max_workflow_retry: int = Field(default=3, ge=1)
    max_review_cycles: int = Field(default=5, ge=1)
    default_context_reset: bool = False
    parallel_result_review: bool = True
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
    input_task_type: Optional[str] = None
    output_task_type: Optional[str] = None
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

    @property
    def root_workflow_id(self) -> str:
        return self.execution.entry_workflow

    def atomic_by_id(self) -> dict[str, AtomicWorkflowDef]:
        return {item.id: item for item in self.workflows.atomic}

    def composite_by_id(self) -> dict[str, CompositeWorkflowDef]:
        return {item.id: item for item in self.workflows.composite}

    def resolve_entry_atomic_workflow(self) -> AtomicWorkflowDef:
        composite_by_id = self.composite_by_id()
        atomic_by_id = self.atomic_by_id()

        def resolve(workflow_id: str, visiting: set[str]) -> AtomicWorkflowDef:
            if workflow_id in visiting:
                raise ValueError(f"workflow cycle detected while resolving entry workflow: {workflow_id}")
            composite = composite_by_id.get(workflow_id)
            if composite is None or not composite.stages:
                raise ValueError(f"entry composite workflow has no stages: {workflow_id}")
            visiting.add(workflow_id)
            try:
                first_stage = sorted(composite.stages, key=lambda item: item.sequence)[0]
                if first_stage.workflow_type == "atomic":
                    atomic = atomic_by_id.get(first_stage.workflow_ref)
                    if atomic is None:
                        raise ValueError(f"unknown atomic workflow in entry chain: {first_stage.workflow_ref}")
                    return atomic
                return resolve(first_stage.workflow_ref, visiting)
            finally:
                visiting.remove(workflow_id)

        return resolve(self.execution.entry_workflow, set())

    def resolve_final_atomic_workflow(self) -> AtomicWorkflowDef:
        composite_by_id = self.composite_by_id()
        atomic_by_id = self.atomic_by_id()

        def resolve(workflow_id: str, visiting: set[str]) -> AtomicWorkflowDef:
            if workflow_id in visiting:
                raise ValueError(f"workflow cycle detected while resolving final workflow: {workflow_id}")
            composite = composite_by_id.get(workflow_id)
            if composite is None or not composite.stages:
                raise ValueError(f"final composite workflow has no stages: {workflow_id}")
            visiting.add(workflow_id)
            try:
                last_stage = sorted(composite.stages, key=lambda item: item.sequence)[-1]
                if last_stage.workflow_type == "atomic":
                    atomic = atomic_by_id.get(last_stage.workflow_ref)
                    if atomic is None:
                        raise ValueError(f"unknown atomic workflow in final chain: {last_stage.workflow_ref}")
                    return atomic
                return resolve(last_stage.workflow_ref, visiting)
            finally:
                visiting.remove(workflow_id)

        return resolve(self.execution.entry_workflow, set())

    def resolve_entry_input_task_type(self) -> str:
        atomic = self.resolve_entry_atomic_workflow()
        return atomic.input_task_type or f"atomic:{atomic.id}:input"

    def resolve_final_output_task_type(self) -> str:
        atomic = self.resolve_final_atomic_workflow()
        return atomic.output_task_type or f"atomic:{atomic.id}:output"

    @model_validator(mode="after")
    def validate_references(self) -> "FrameworkConfig":
        agent_ids = {item.id for item in self.agents}
        plugin_ids = {item.id for item in self.plugins}
        atomic_ids = {item.id for item in self.workflows.atomic}
        composite_ids = {item.id for item in self.workflows.composite}

        if len(agent_ids) != len(self.agents):
            raise ValueError("duplicated agent ids detected")
        if len(plugin_ids) != len(self.plugins):
            raise ValueError("duplicated plugin ids detected")
        if len(atomic_ids) != len(self.workflows.atomic):
            raise ValueError("duplicated atomic workflow ids detected")
        if len(composite_ids) != len(self.workflows.composite):
            raise ValueError("duplicated composite workflow ids detected")
        if atomic_ids & composite_ids:
            raise ValueError("workflow ids must be unique across atomic/composite definitions")

        for wf in self.workflows.atomic:
            if wf.roles.worker.agent_id not in agent_ids:
                raise ValueError(f"atomic workflow '{wf.id}' worker agent '{wf.roles.worker.agent_id}' not found")
            for advisor in wf.roles.advisors.global_review + wf.roles.advisors.result_review:
                if advisor.agent_id not in agent_ids:
                    raise ValueError(
                        f"atomic workflow '{wf.id}' advisor '{advisor.instance_id}' agent '{advisor.agent_id}' not found"
                    )
            for plugin_id in wf.start_plugins + wf.end_plugins:
                if plugin_id not in plugin_ids:
                    raise ValueError(f"atomic workflow '{wf.id}' plugin '{plugin_id}' not found")

        all_workflow_ids = atomic_ids | composite_ids
        for wf in self.workflows.composite:
            if not wf.stages:
                raise ValueError(f"composite workflow '{wf.id}' must have at least one stage")
            for stage in wf.stages:
                if stage.workflow_ref not in all_workflow_ids:
                    raise ValueError(
                        f"composite workflow '{wf.id}' stage '{stage.stage_id}' references unknown workflow '{stage.workflow_ref}'"
                    )
                if stage.workflow_type == "atomic" and stage.workflow_ref not in atomic_ids:
                    raise ValueError(
                        f"composite workflow '{wf.id}' stage '{stage.stage_id}' declares atomic but references '{stage.workflow_ref}'"
                    )
                if stage.workflow_type == "composite" and stage.workflow_ref not in composite_ids:
                    raise ValueError(
                        f"composite workflow '{wf.id}' stage '{stage.stage_id}' declares composite but references '{stage.workflow_ref}'"
                    )

        if self.execution.entry_workflow_type != "composite":
            raise ValueError("execution.entry_workflow_type must be 'composite'")
        if self.execution.entry_workflow not in composite_ids:
            raise ValueError("execution.entry_workflow must reference a composite workflow")

        graph = {
            wf.id: {stage.workflow_ref for stage in wf.stages if stage.workflow_type == "composite"}
            for wf in self.workflows.composite
        }
        visited: set[str] = set()
        stack: set[str] = set()

        def dfs(node: str) -> None:
            if node in stack:
                raise ValueError(f"detected composite workflow cycle at '{node}'")
            if node in visited:
                return
            visited.add(node)
            stack.add(node)
            for next_node in graph.get(node, set()):
                dfs(next_node)
            stack.remove(node)

        for workflow_id in composite_ids:
            dfs(workflow_id)

        self.resolve_entry_input_task_type()
        self.resolve_final_output_task_type()
        return self
