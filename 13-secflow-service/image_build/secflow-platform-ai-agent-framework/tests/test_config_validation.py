from __future__ import annotations


def test_root_config_is_valid(framework_config):
    assert framework_config.root_workflow_id == "secflow_vuln_pipeline"
    assert len(framework_config.atomic_workflows) == 7
    assert len(framework_config.composite_workflows) == 1


def test_composite_stage_chain_is_linear(framework_config):
    workflow = framework_config.composite_workflows[0]
    ordered = [stage.id for stage in workflow.stages]
    assert ordered == [
        "stage_package_unpack",
        "stage_system_analysis",
        "stage_decompile_optimize",
        "stage_external_entry_analysis",
        "stage_dataflow_analysis",
        "stage_vuln_identify",
        "stage_vuln_filter",
    ]
