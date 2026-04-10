from __future__ import annotations

import json
from pathlib import Path

from app.engine.workflow import WorkflowExecutor
from app.models.config_models import FrameworkConfig


def test_full_pipeline_run(framework_root, framework_config, tmp_path):
    executor = WorkflowExecutor(framework_config)
    result = executor.run(str(framework_root / "examples" / "input_tasks.json"), str(tmp_path / "workspace"))

    assert result.state.value == "succeeded"
    assert Path(result.output_manifest_path).exists()
    payload = json.loads(Path(result.output_manifest_path).read_text(encoding="utf-8"))
    assert payload["tasks"] == []

    root_dir = tmp_path / "workspace" / framework_config.root_workflow_id
    assert (root_dir / "stage_package_unpack" / "stage_summary.json").exists()
    assert (root_dir / "stage_vuln_filter" / "stage_summary.json").exists()


def test_feedback_loop_reaches_second_round(framework_root, framework_config_payload, tmp_path):
    payload = framework_config_payload
    payload["prompts"]["global_review_user"] = "REQUIRE_FEEDBACK_LOOP Review the full task outcome."
    config = FrameworkConfig.model_validate(payload)
    executor = WorkflowExecutor(config)
    result = executor.run(str(framework_root / "examples" / "input_tasks.json"), str(tmp_path / "workspace"))

    assert result.state.value == "succeeded"
    attempt_dir = (
        tmp_path
        / "workspace"
        / config.root_workflow_id
        / "stage_package_unpack"
        / "package-list-001"
        / "attempt-001"
    )
    assert (attempt_dir / "review_feedback" / "round-001.json").exists()
    assert (attempt_dir / "round-002" / "summary.json").exists()
