from __future__ import annotations


def test_root_config_is_valid(framework_config):
    assert framework_config.root_workflow_id == "test_pipeline"
    assert len(framework_config.workflows.atomic) == 1
    assert len(framework_config.workflows.composite) == 1
    assert framework_config.resolve_entry_input_task_type() == "atomic:test_vuln_scan:input"
    assert framework_config.resolve_final_output_task_type() == "atomic:test_vuln_scan:output"


def test_composite_stage_sequence_is_linear(framework_config):
    workflow = framework_config.workflows.composite[0]
    ordered = [stage.stage_id for stage in sorted(workflow.stages, key=lambda item: item.sequence)]
    assert ordered == ["stage_01_scan"]
