from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.workflow import ExitWorkflowError, RetryWorkflowError, WorkflowExecutor
from app.models.config_models import FrameworkConfig
from app.models.contracts import ExecutionState, PluginStatus, TaskItem
from app.plugins.base import PluginExecutionContext


@pytest.mark.parametrize(
    ("status", "expected_state", "expected_exception"),
    [
        ("SUCCESS_NEXT", None, None),
        ("SUCCESS_END_STAGE", None, None),
        ("RETRY_WORKFLOW", None, RetryWorkflowError),
        ("FAIL_END_STAGE_CONTINUE", ExecutionState.ABNORMAL_CONTINUE, None),
        ("FAIL_EXIT_WORKFLOW", None, ExitWorkflowError),
        ("FAIL_CONTINUE_NEXT_PLUGIN", None, None),
    ],
)
def test_plugin_phase_statuses(status, expected_state, expected_exception, framework_config_payload, tmp_path):
    payload = framework_config_payload
    payload["plugins"].append(
        {
            "id": "test_plugin",
            "kind": "python",
            "module": "plugins.workflow_plugins",
            "class_name": "WorkflowControlPlugin",
            "config": {"status": status, "message": status},
        }
    )
    executor = WorkflowExecutor(FrameworkConfig.model_validate(payload))
    workflow = executor.framework_config.atomic_workflows[0]
    ctx = PluginExecutionContext(
        framework_config=executor.framework_config,
        workflow_config=workflow,
        plugin_definition=None,
        phase="pre",
        task=TaskItem(
            task_id="task-001",
            task_type=workflow.input_task_type,
            title="Plugin test",
            task_md_path="/tmp/task.md",
            metadata={},
            upstream_refs=[],
        ),
        task_dir=Path(tmp_path),
        workspace_root=Path(tmp_path),
        round_no=0,
        runtime_manager=executor.runtime_manager,
    )
    if expected_exception:
        with pytest.raises(expected_exception):
            executor._run_plugin_phase(plugin_ids=["test_plugin"], ctx=ctx, phase_dir=Path(tmp_path) / "phase")
    else:
        outcome = executor._run_plugin_phase(plugin_ids=["test_plugin"], ctx=ctx, phase_dir=Path(tmp_path) / "phase")
        assert outcome.stage_state == expected_state
