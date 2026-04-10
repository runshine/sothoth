from __future__ import annotations

from pathlib import Path

import pytest

from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config


@pytest.mark.asyncio
async def test_full_pipeline_run(framework_config_payload: dict, tmp_path: Path, patch_mock_agent_runtime):
    input_task = tmp_path / "input-task.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config = build_runtime_framework_config(
        framework_config_payload,
        workspace_root=str(tmp_path / "workspace"),
        execution_id="test-run-001",
        input_task_file=str(input_task),
        input_task_id="task-001",
        output_dir=str(tmp_path / "output"),
        summary_file=str(tmp_path / "output" / "execution_summary.json"),
        runtime_mode="local_test",
    )
    artifacts = await run_framework_config(config)

    assert artifacts.result.success is True
    assert len(artifacts.result.final_tasks) == 2
    assert Path(artifacts.summary_file or "").exists()
    assert (Path(artifacts.result.working_dir) / "_meta" / "workflow_result.json").exists()
    assert (Path(artifacts.result.working_dir) / "stage_01_scan").exists()


@pytest.mark.asyncio
async def test_summary_and_review_artifacts_are_recorded(framework_config_payload: dict, tmp_path: Path, patch_mock_agent_runtime):
    input_task = tmp_path / "input-task.md"
    input_task.write_text("# Test Task\n\nAnalyze mock binary.\n", encoding="utf-8")

    config = build_runtime_framework_config(
        framework_config_payload,
        workspace_root=str(tmp_path / "workspace"),
        execution_id="test-run-002",
        input_task_file=str(input_task),
        input_task_id="task-002",
        output_dir=str(tmp_path / "output"),
        summary_file=str(tmp_path / "output" / "execution_summary.json"),
        runtime_mode="local_test",
    )
    artifacts = await run_framework_config(config)
    workflow_dir = Path(artifacts.result.working_dir)

    assert list(workflow_dir.rglob("summary.md"))
    assert list(workflow_dir.rglob("reviews/global/**/*.json"))
    assert list(workflow_dir.rglob("reviews/results/**/*.json"))
