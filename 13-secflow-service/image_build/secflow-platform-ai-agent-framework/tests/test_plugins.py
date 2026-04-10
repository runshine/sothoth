from __future__ import annotations

import pytest

from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
from app.pi_vuln_core.plugins.executor import PluginChainExecutor
from app.pi_vuln_core.plugins.registry import PluginRegistry


class StaticPlugin(BasePlugin):
    def __init__(self, plugin_id: str, code: PluginResultCode):
        self._plugin_id = plugin_id
        self._code = code

    @property
    def plugin_id(self) -> str:
        return self._plugin_id

    async def execute(self, ctx: PluginContext) -> PluginResult:
        return PluginResult(code=self._code, message=self._code.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "expected_action"),
    [
        (PluginResultCode.OK_NEXT, "completed"),
        (PluginResultCode.OK_END_STAGE, "end_stage_normal"),
        (PluginResultCode.ERROR_CONTINUE, "completed"),
        (PluginResultCode.ERROR_END_NEXT, "end_stage_skip_next"),
        (PluginResultCode.ERROR_RESTART, "restart_workflow"),
        (PluginResultCode.ERROR_EXIT, "exit_workflow"),
    ],
)
async def test_plugin_phase_statuses(code: PluginResultCode, expected_action: str):
    registry = PluginRegistry()
    registry.register_instance("test_plugin", StaticPlugin("test_plugin", code), config={})
    executor = PluginChainExecutor(registry)
    result = await executor.execute_chain(
        ["test_plugin"],
        PluginContext(
            workflow_id="wf",
            task_id="task",
            execution_id="exec",
            working_dir="/tmp",
            task_file="/tmp/task.md",
            plugin_config={},
            shared_state={},
            global_config={},
        ),
        phase="start",
    )
    assert result.action == expected_action
