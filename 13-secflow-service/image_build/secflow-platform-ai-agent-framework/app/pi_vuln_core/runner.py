from __future__ import annotations

import copy
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.loader import ConfigLoader
from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.engine.composite import CompositeWorkflowEngine
from app.pi_vuln_core.engine.models import CompositeWorkflowResult, TaskItem
from app.pi_vuln_core.observer import ExecutionObserver, NullExecutionObserver
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.plugins.registry import PluginRegistry
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.logger import get_logger, setup_logging
from app.pi_vuln_core.workspace.manager import WorkspaceManager

logger = get_logger("pi_vuln_runner")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class RunnerArtifacts:
    config: FrameworkConfig
    result: CompositeWorkflowResult
    summary_file: str | None


def load_framework_config_from_path(config_path: str | Path) -> FrameworkConfig:
    return ConfigLoader.load(config_path)


def _resolve_prompt_paths_inplace(obj, *, base_dir: Path) -> None:
    prompt_keys = {
        "system_prompt_file", "user_prompt_file",
        "user_prompt_template", "prompt_file",
    }
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in prompt_keys and isinstance(value, str) and not os.path.isabs(value):
                obj[key] = str(base_dir / value)
            else:
                _resolve_prompt_paths_inplace(value, base_dir=base_dir)
    elif isinstance(obj, list):
        for item in obj:
            _resolve_prompt_paths_inplace(item, base_dir=base_dir)


def build_runtime_framework_config(
    definition_json: dict,
    *,
    workspace_root: str,
    execution_id: str,
    input_task_file: str,
    input_task_id: str,
    output_dir: str,
    summary_file: str,
    runtime_mode: str = "rest_service",
) -> FrameworkConfig:
    payload = copy.deepcopy(definition_json)
    _resolve_prompt_paths_inplace(payload, base_dir=PROJECT_ROOT)
    payload.setdefault("execution", {})
    payload.setdefault("global", {})
    payload["global"]["workspace_root"] = workspace_root
    execution = payload["execution"]
    execution["execution_id"] = execution_id
    execution["runtime_mode"] = runtime_mode
    execution["output_dir"] = output_dir
    execution["input_task"] = {
        "task_file": input_task_file,
        "task_id": input_task_id,
    }
    completion = execution.setdefault("on_completion", {})
    completion["summary_file"] = summary_file
    completion.setdefault("write_summary", True)
    completion.setdefault("exit_code_on_success", 0)
    completion.setdefault("exit_code_on_failure", 1)
    return FrameworkConfig.model_validate(payload)


async def run_framework_config(
    config: FrameworkConfig,
    *,
    initial_tasks: list[TaskItem] | None = None,
    observer: ExecutionObserver | None = None,
    recorder: ExecutionRecorder | None = None,
    clean_workspace: bool = False,
) -> RunnerArtifacts:
    observer = observer or NullExecutionObserver()
    setup_logging(config.global_config.log_level)
    workspace_root = config.global_config.workspace_root
    agent_registry: AgentRuntimeRegistry | None = None

    try:
        for key, value in config.global_config.env_vars.items():
            os.environ.setdefault(key, value)

        agent_registry = AgentRuntimeRegistry()
        agent_registry.register_from_config([item.model_dump() for item in config.agents])
        await agent_registry.initialize_all()

        plugin_registry = PluginRegistry()
        plugin_registry.register_from_config([item.model_dump() for item in config.plugins])

        workspace = WorkspaceManager(workspace_root)
        recorder = recorder or ExecutionRecorder(workspace_root)
        plugin_executor = PluginChainExecutor(plugin_registry)
        engine = CompositeWorkflowEngine(
            config=config,
            agent_registry=agent_registry,
            plugin_executor=plugin_executor,
            workspace=workspace,
            recorder=recorder,
            observer=observer,
        )

        exec_cfg = config.execution
        Path(exec_cfg.output_dir).mkdir(parents=True, exist_ok=True)
        if initial_tasks:
            result = await engine.run_tasks(
                workflow_id=exec_cfg.entry_workflow,
                tasks=initial_tasks,
                execution_id=exec_cfg.execution_id,
            )
        else:
            result = await engine.run(
                workflow_id=exec_cfg.entry_workflow,
                input_task_file=exec_cfg.input_task.task_file,
                execution_id=exec_cfg.execution_id,
            )

        summary_file = exec_cfg.on_completion.summary_file if exec_cfg.on_completion.write_summary else None
        if summary_file:
            write_json(summary_file, result.to_dict())
        return RunnerArtifacts(config=config, result=result, summary_file=summary_file)
    finally:
        if agent_registry:
            try:
                await agent_registry.shutdown_all()
            except Exception:
                logger.warning("agent_registry_shutdown_failed", exc_info=True)
        if clean_workspace and workspace_root and os.path.isdir(workspace_root):
            shutil.rmtree(workspace_root, ignore_errors=True)
