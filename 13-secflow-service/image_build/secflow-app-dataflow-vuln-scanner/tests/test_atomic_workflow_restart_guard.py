from __future__ import annotations

import pytest

from app.pi_vuln_core.config.models import (
    AtomicWorkflowDef,
    GlobalConfig,
    RolesDef,
    SummaryPromptConfig,
    WorkerPromptsConfig,
    WorkerRoleDef,
    WorkPromptConfig,
)
from app.pi_vuln_core.engine.atomic import AtomicWorkflowEngine
from app.pi_vuln_core.engine.models import AtomicWorkflowResult
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.workspace.manager import WorkspaceManager


def _minimal_workflow() -> AtomicWorkflowDef:
    return AtomicWorkflowDef(
        id="wf",
        name="workflow",
        working_dir_template="{task_id}",
        roles=RolesDef(
            worker=WorkerRoleDef(
                agent_id="pi-worker",
                prompts=WorkerPromptsConfig(
                    work=WorkPromptConfig(system_prompt_file="", user_prompt_file=""),
                    summary=SummaryPromptConfig(prompt_file=""),
                ),
            )
        ),
    )


@pytest.mark.asyncio
async def test_restart_workflow_action_is_not_reexecuted(tmp_path, monkeypatch):
    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    calls = 0

    async def fake_execute_once(self, work_dir: str, input_task: str, task_id: str) -> AtomicWorkflowResult:
        nonlocal calls
        calls += 1
        return AtomicWorkflowResult(
            status="failed",
            action="restart_workflow",
            working_dir=work_dir,
            error="plugin requested restart",
        )

    monkeypatch.setattr(AtomicWorkflowEngine, "_execute_once", fake_execute_once)
    engine = AtomicWorkflowEngine(
        _minimal_workflow(),
        agent_registry=None,
        plugin_executor=None,
        workspace=WorkspaceManager(str(tmp_path / "workspace")),
        recorder=ExecutionRecorder(),
        global_config=GlobalConfig(max_workflow_retry=3),
    )

    result = await engine.run(str(task_file), "task-001")

    assert calls == 1
    assert result.status == "failed"
    assert result.action == "restart_workflow"
    assert result.error == "plugin requested restart"
