from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from app.models.config_models import AtomicWorkflowConfig, FrameworkConfig, PluginDefinition
from app.models.contracts import PluginResult, TaskItem
from app.runtime.registry import RuntimeManager


@dataclass
class PluginExecutionContext:
    framework_config: FrameworkConfig
    workflow_config: AtomicWorkflowConfig
    plugin_definition: Optional[PluginDefinition]
    phase: str
    task: TaskItem
    task_dir: Path
    workspace_root: Path
    round_no: int
    runtime_manager: RuntimeManager
    shared_state: Dict[str, Any] = field(default_factory=dict)
    summary_json_path: Optional[Path] = None
    results_manifest_path: Optional[Path] = None
    feedback_json_path: Optional[Path] = None
    next_task_manifest_path: Optional[Path] = None


class BasePlugin:
    def __init__(self, plugin_definition: Optional[PluginDefinition] = None):
        self.plugin_definition = plugin_definition

    @property
    def plugin_id(self) -> str:
        if self.plugin_definition:
            return self.plugin_definition.id
        return self.__class__.__name__

    @property
    def config(self) -> Dict[str, Any]:
        if not self.plugin_definition:
            return {}
        return self.plugin_definition.config

    def execute(self, ctx: PluginExecutionContext) -> PluginResult:
        raise NotImplementedError
