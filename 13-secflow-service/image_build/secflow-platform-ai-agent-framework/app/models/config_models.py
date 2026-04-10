from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import ConfigDict, Field, model_validator

from app.models.contracts import SessionMode, StrictModel, TaskFailurePolicy, WorkflowKind


class CommandOrSdkConfig(StrictModel):
    kind: Literal["command"] = "command"
    command: str = Field(..., min_length=1)
    args: List[str] = Field(default_factory=list)


class AgentTypeRuntimeConfig(StrictModel):
    adapter: str = Field(..., min_length=1)
    session_mode_default: SessionMode = SessionMode.INVOKE
    command_or_sdk: CommandOrSdkConfig
    env_from: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None


class AgentTypeConfig(StrictModel):
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)
    runtime: AgentTypeRuntimeConfig


class AgentRuntimeOverrideConfig(StrictModel):
    session_mode: Optional[SessionMode] = None
    cwd: Optional[str] = None
    env: Dict[str, str] = Field(default_factory=dict)
    command_or_sdk: Optional[CommandOrSdkConfig] = None


class AgentInstanceConfig(StrictModel):
    id: str = Field(..., min_length=1)
    agent_type_id: str = Field(..., min_length=1)
    reset_context: bool
    runtime_overrides: Optional[AgentRuntimeOverrideConfig] = None


class PluginDefinition(StrictModel):
    id: str = Field(..., min_length=1)
    kind: Literal["python", "builtin"] = "python"
    module: Optional[str] = None
    class_name: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_plugin_locator(self) -> "PluginDefinition":
        if self.kind == "python" and (not self.module or not self.class_name):
            raise ValueError("python plugin requires module and class_name")
        return self


class WorkerBinding(StrictModel):
    agent_instance_id: str = Field(..., min_length=1)
    task_prompt_ref: str = Field(..., min_length=1)
    session_mode_override: Optional[SessionMode] = None


class SummaryBinding(StrictModel):
    prompt_ref: str = Field(..., min_length=1)


class ReviewerBinding(StrictModel):
    id: str = Field(..., min_length=1)
    agent_instance_id: str = Field(..., min_length=1)
    system_prompt_ref: str = Field(..., min_length=1)
    user_prompt_ref: str = Field(..., min_length=1)
    rerun_on_next_round: Optional[bool] = None


class AdvisorBinding(StrictModel):
    global_reviewers: List[ReviewerBinding] = Field(default_factory=list)
    result_reviewers: List[ReviewerBinding] = Field(default_factory=list)


class AtomicWorkflowConfig(StrictModel):
    id: str = Field(..., min_length=1)
    input_task_type: str = Field(..., min_length=1)
    output_task_type: str = Field(..., min_length=1)
    max_rounds: int = Field(..., ge=1)
    max_restart_attempts: int = Field(..., ge=0)
    pre_plugins: List[str] = Field(default_factory=list)
    worker: WorkerBinding
    reflection_prompt_refs: List[str] = Field(default_factory=list)
    summary: SummaryBinding
    advisor: AdvisorBinding
    post_plugins: List[str] = Field(default_factory=list)


class CompositeStageConfig(StrictModel):
    id: str = Field(..., min_length=1)
    workflow_kind: WorkflowKind
    workflow_ref: str = Field(..., min_length=1)
    previous_stage_id: Optional[str] = None
    next_stage_id: Optional[str] = None
    task_failure_policy: TaskFailurePolicy = TaskFailurePolicy.CONTINUE


class CompositeWorkflowConfig(StrictModel):
    id: str = Field(..., min_length=1)
    stages: List[CompositeStageConfig] = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_linear_chain(self) -> "CompositeWorkflowConfig":
        stage_map = {stage.id: stage for stage in self.stages}
        if len(stage_map) != len(self.stages):
            raise ValueError(f"composite workflow {self.id} contains duplicated stage ids")

        heads = [stage for stage in self.stages if stage.previous_stage_id is None]
        tails = [stage for stage in self.stages if stage.next_stage_id is None]
        if len(heads) != 1 or len(tails) != 1:
            raise ValueError(f"composite workflow {self.id} must have exactly one head and one tail")

        for stage in self.stages:
            if stage.previous_stage_id is not None and stage.previous_stage_id not in stage_map:
                raise ValueError(f"stage {stage.id} references unknown previous_stage_id {stage.previous_stage_id}")
            if stage.next_stage_id is not None and stage.next_stage_id not in stage_map:
                raise ValueError(f"stage {stage.id} references unknown next_stage_id {stage.next_stage_id}")
            if stage.previous_stage_id == stage.id or stage.next_stage_id == stage.id:
                raise ValueError(f"stage {stage.id} cannot reference itself")

        for stage in self.stages:
            if stage.next_stage_id:
                next_stage = stage_map[stage.next_stage_id]
                if next_stage.previous_stage_id != stage.id:
                    raise ValueError(f"stage {stage.id} next_stage_id is not bidirectional")
            if stage.previous_stage_id:
                previous_stage = stage_map[stage.previous_stage_id]
                if previous_stage.next_stage_id != stage.id:
                    raise ValueError(f"stage {stage.id} previous_stage_id is not bidirectional")

        ordered = []
        current = heads[0]
        visited = set()
        while current:
            if current.id in visited:
                raise ValueError(f"composite workflow {self.id} contains a cycle")
            visited.add(current.id)
            ordered.append(current.id)
            current = stage_map.get(current.next_stage_id) if current.next_stage_id else None

        if len(ordered) != len(self.stages):
            raise ValueError(f"composite workflow {self.id} must be a single linear chain")
        return self


class NextTaskGeneratorConfig(StrictModel):
    agent_instance_id: str = Field(..., min_length=1)
    system_prompt_ref: str = Field(..., min_length=1)
    user_prompt_ref: str = Field(..., min_length=1)
    allow_empty: bool = True


class RunConfig(StrictModel):
    next_task_generator: NextTaskGeneratorConfig
    session_quiet_window_ms: int = Field(default=450, ge=1)
    session_max_window_ms: int = Field(default=10000, ge=1)
    plugin_search_packages: List[str] = Field(default_factory=lambda: ["plugins"])


class FrameworkConfig(StrictModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(..., min_length=1)
    run: RunConfig
    prompts: Dict[str, str] = Field(default_factory=dict)
    agent_types: List[AgentTypeConfig]
    agent_instances: List[AgentInstanceConfig]
    plugins: List[PluginDefinition] = Field(default_factory=list)
    atomic_workflows: List[AtomicWorkflowConfig]
    composite_workflows: List[CompositeWorkflowConfig]
    root_workflow_id: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_references(self) -> "FrameworkConfig":
        prompt_ids = set(self.prompts)
        agent_type_ids = {item.id for item in self.agent_types}
        if len(agent_type_ids) != len(self.agent_types):
            raise ValueError("duplicated agent_types.id detected")

        agent_instance_ids = {item.id for item in self.agent_instances}
        if len(agent_instance_ids) != len(self.agent_instances):
            raise ValueError("duplicated agent_instances.id detected")
        for item in self.agent_instances:
            if item.agent_type_id not in agent_type_ids:
                raise ValueError(f"agent instance {item.id} references unknown agent_type_id {item.agent_type_id}")

        plugin_ids = {plugin.id for plugin in self.plugins}
        if len(plugin_ids) != len(self.plugins):
            raise ValueError("duplicated plugins.id detected")

        atomic_ids = {item.id for item in self.atomic_workflows}
        composite_ids = {item.id for item in self.composite_workflows}
        if len(atomic_ids) != len(self.atomic_workflows):
            raise ValueError("duplicated atomic_workflows.id detected")
        if len(composite_ids) != len(self.composite_workflows):
            raise ValueError("duplicated composite_workflows.id detected")
        if atomic_ids & composite_ids:
            raise ValueError("workflow ids must be unique across atomic and composite workflows")

        for workflow in self.atomic_workflows:
            if workflow.worker.agent_instance_id not in agent_instance_ids:
                raise ValueError(f"atomic workflow {workflow.id} worker references unknown agent instance")
            if workflow.worker.task_prompt_ref not in prompt_ids:
                raise ValueError(f"atomic workflow {workflow.id} worker prompt ref not found")
            if workflow.summary.prompt_ref not in prompt_ids:
                raise ValueError(f"atomic workflow {workflow.id} summary prompt ref not found")
            for prompt_ref in workflow.reflection_prompt_refs:
                if prompt_ref not in prompt_ids:
                    raise ValueError(f"atomic workflow {workflow.id} reflection prompt ref not found: {prompt_ref}")
            for plugin_id in workflow.pre_plugins + workflow.post_plugins:
                if not (plugin_id in plugin_ids or plugin_id.startswith("builtin.")):
                    raise ValueError(f"atomic workflow {workflow.id} references unknown plugin {plugin_id}")
            for reviewer in workflow.advisor.global_reviewers + workflow.advisor.result_reviewers:
                if reviewer.agent_instance_id not in agent_instance_ids:
                    raise ValueError(f"reviewer {reviewer.id} references unknown agent instance")
                if reviewer.system_prompt_ref not in prompt_ids:
                    raise ValueError(f"reviewer {reviewer.id} system_prompt_ref not found")
                if reviewer.user_prompt_ref not in prompt_ids:
                    raise ValueError(f"reviewer {reviewer.id} user_prompt_ref not found")

        for workflow in self.composite_workflows:
            for stage in workflow.stages:
                if stage.workflow_kind == WorkflowKind.ATOMIC and stage.workflow_ref not in atomic_ids:
                    raise ValueError(f"composite stage {stage.id} references unknown atomic workflow {stage.workflow_ref}")
                if stage.workflow_kind == WorkflowKind.COMPOSITE and stage.workflow_ref not in composite_ids:
                    raise ValueError(f"composite stage {stage.id} references unknown composite workflow {stage.workflow_ref}")
                if stage.workflow_kind == WorkflowKind.COMPOSITE and stage.workflow_ref == workflow.id:
                    raise ValueError(f"composite workflow {workflow.id} cannot recursively reference itself")

        if self.root_workflow_id not in composite_ids:
            raise ValueError("root_workflow_id must reference a composite workflow")

        generator = self.run.next_task_generator
        if generator.agent_instance_id not in agent_instance_ids:
            raise ValueError("run.next_task_generator.agent_instance_id not found")
        if generator.system_prompt_ref not in prompt_ids or generator.user_prompt_ref not in prompt_ids:
            raise ValueError("run.next_task_generator prompt refs not found")
        return self
