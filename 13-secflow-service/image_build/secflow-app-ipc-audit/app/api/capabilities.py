from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_config
from app.schemas import CapabilityResponse
from app.services.runtime_config_service import get_runtime_config_service

router = APIRouter()


@router.get("/capabilities", response_model=CapabilityResponse)
def get_capabilities() -> CapabilityResponse:
    cfg = get_config()
    default_workspace = next((item for item in cfg.workspaces if item.workspace_id == cfg.default_workspace_id), None)
    pipeline_modes = ["custom_graph"]
    executor_modes: list[str] = ["agentflow_cli", "codex_cli", "opencode_cli"]
    if cfg.execution.mode == "mock":
        executor_modes.insert(0, "mock")
    elif cfg.execution.mode in executor_modes:
        executor_modes.remove(cfg.execution.mode)
        executor_modes.insert(0, cfg.execution.mode)
    return CapabilityResponse(
        service="secflow-app-ipc-audit",
        runtime_mode=f"embedded_worker:{cfg.execution.mode}",
        pipeline_modes=pipeline_modes,
        executor_modes=executor_modes,
        default_executor_mode=cfg.execution.mode,
        input_kinds=["preset_project", "custom_project", "existing_audit_report"],
        allow_custom_project_path=default_workspace.allow_custom_project_path if default_workspace else True,
        show_scan_strategy=False,
        supports_sessions=True,
        supports_sse=True,
        supports_poc=cfg.execution.poc_enabled,
        poc_runtime_available=cfg.execution.poc_runtime_available,
        default_workspace_id=cfg.default_workspace_id,
        default_pipeline_mode="custom_graph",
        artifact_kinds=[
            "audit_report",
            "audit_log",
            "poc_report",
            "poc_log",
            "audited_result_json",
            "report_output",
            "stage_log",
            "graph_manifest",
            "runtime_manifest",
            "session_file",
        ],
        max_parallel_tasks=get_runtime_config_service().get_max_parallel_tasks(),
    )
